"""Pure synthetic packet/rule schemas and static conflict analysis.

These addresses/ports are metadata in a simulator, never socket endpoints.
No counters, clocks, detection windows or reputation are changed here.
"""
from ipaddress import IPv4Address

NODE_IPS = {**{f'V{i:02}':f'10.0.0.{i}' for i in range(1,13)},
            **{f'RSU-{i}':f'10.0.1.{i}' for i in range(1,4)}}
PORTS = {'SAFETY':5005,'UDP_FLOOD':9999,'TELEMETRY':9000,'BEACON':9001}
MATCH_FIELDS = ('source','destination','traffic','rsu','source_ip','destination_ip','protocol','src_port','dst_port')
PRECEDENCE = ('Highest-priority static selection (tie: rule ID), static DROP, '
              'M2 temporary DROP, all applicable independent meter budgets, normal forwarding. '
              'ALLOW never bypasses dynamic protection. Safety is exempt from M2/M3 meters; '
              'explicit static safety rules still apply.')


def integer(value, name, low, high):
    if isinstance(value,str) and value.isascii() and value.isdigit():value=int(value)
    if type(value) is not int or not low<=value<=high:
        raise ValueError(f'{name} must be an integer between {low} and {high}')
    return value


def ip(value, name, wildcard=True):
    if wildcard and value=='*':return value
    if not isinstance(value,str):raise ValueError(f'{name} requires an IPv4 address')
    try:return str(IPv4Address(value))
    except ValueError:raise ValueError(f'{name} requires an IPv4 address or *' if wildcard else f'{name} requires an IPv4 address') from None


def validate_rule(data, rule_id):
    if not isinstance(data,dict):raise ValueError('Rule must be a JSON object')
    if not isinstance(rule_id,str) or not rule_id or len(rule_id)>80 or rule_id.startswith(('m2-','m3-','system-')):
        raise ValueError('Invalid or reserved static rule ID')
    if data.get('id') not in (None,'',rule_id):raise ValueError('Rule ID is read-only')
    allowed=set(MATCH_FIELDS)|{'id','priority','label','action','enabled','rate_kbps'}
    if set(data)-allowed:raise ValueError('Unknown or read-only rule fields: '+', '.join(sorted(set(data)-allowed)))
    result={'id':rule_id,'priority':integer(data.get('priority',500),'Priority',1,999)}
    for field in ('source','destination'):
        value=data.get(field,'*')
        if not isinstance(value,str) or value not in ('*',*NODE_IPS):raise ValueError(f'Unknown {field}')
        result[field]=value
    for field in ('traffic','rsu','protocol'):
        choices={'traffic':('*',*PORTS),'rsu':('*','RSU-1','RSU-2','RSU-3'),'protocol':('*','UDP','TCP','ICMP')}[field]
        value=data.get(field,'*')
        if value not in choices:raise ValueError(f'Invalid {field}')
        result[field]=value
    for field in ('source_ip','destination_ip'):result[field]=ip(data.get(field,'*'),field)
    for field in ('src_port','dst_port'):
        value=data.get(field)
        result[field]=None if value in (None,'','*') else integer(value,field,0,65535)
    if result['protocol']=='ICMP' and any(result[k] is not None for k in ('src_port','dst_port')):
        raise ValueError('ICMP rules cannot match transport ports')
    action=data.get('action','DROP')
    if action not in ('ALLOW','DROP','METER'):raise ValueError('Invalid action')
    if type(data.get('enabled',True)) is not bool:raise ValueError('Enabled must be true/false')
    label=data.get('label','Custom rule')
    if not isinstance(label,str) or len(label)>80:raise ValueError('Rule name must be at most 80 characters')
    result.update(action=action,enabled=data.get('enabled',True),label=label.strip() or 'Custom rule',
                  rate_kbps=integer(data.get('rate_kbps',500),'Rate',10,50000) if action=='METER' else None)
    return result


def packet_for(source,destination,traffic,size,rsu):
    return dict(source=source,destination=destination,traffic=traffic,rsu=rsu,
                source_ip=NODE_IPS.get(source),destination_ip=NODE_IPS.get(destination),
                protocol='UDP',src_port=40000+int(source[1:]) if source.startswith('V') else 9001,
                dst_port=PORTS[traffic],size=size)


def validate_packet(data, vehicles):
    if not isinstance(data,dict):raise ValueError('Packet must be a JSON object')
    allowed={'source_ip','destination_ip','protocol','src_port','dst_port','size','rsu'}
    if set(data)-allowed:raise ValueError('Unknown packet fields')
    src,dst=ip(data.get('source_ip'),'source_ip',False),ip(data.get('destination_ip'),'destination_ip',False)
    protocol=data.get('protocol','UDP')
    if protocol not in ('UDP','TCP','ICMP'):raise ValueError('Protocol must be UDP, TCP or ICMP')
    ports={key:None if data.get(key) in (None,'') else integer(data[key],key,0,65535) for key in ('src_port','dst_port')}
    if protocol=='ICMP' and any(v is not None for v in ports.values()):raise ValueError('ICMP has no transport ports')
    if protocol!='ICMP' and any(v is None for v in ports.values()):raise ValueError('UDP/TCP previews require both ports')
    identities={address:node for node,address in NODE_IPS.items()}
    source,destination=identities.get(src),identities.get(dst)
    rsu=data.get('rsu',vehicles[source].rsu if source in vehicles else source if source and source.startswith('RSU-') else None)
    if rsu not in (None,'RSU-1','RSU-2','RSU-3'):raise ValueError('Unknown ingress RSU')
    traffic=next((k for k,v in PORTS.items() if protocol=='UDP' and v==ports['dst_port']),'TELEMETRY')
    return dict(source=source,destination=destination,source_ip=src,destination_ip=dst,protocol=protocol,
                traffic=traffic,rsu=rsu,size=integer(data.get('size',1024),'Packet size',1,65535),**ports)


def matches(rule, packet):
    return rule['enabled'] and all(rule.get(k,'*' if k not in ('src_port','dst_port') else None) in ('*',None,packet.get(k))
                                   for k in MATCH_FIELDS)


def analyze_rules(rules, focus=None):
    """Conservative pairwise warnings; never rejects valid intentional overrides."""
    warnings=[]
    warning_count=0
    def warn(record):
        nonlocal warning_count
        if focus and focus not in (record['rule_id'],record.get('other_id')):return
        warning_count+=1
        if len(warnings)<256:warnings.append(record)
    ordered=sorted((r for r in rules if r['enabled']),key=lambda r:(-r['priority'],r['id']))
    def wildcard(value):return value in ('*',None)
    def predicate(r):
        p={k:r.get(k,None if k.endswith('_port') else '*') for k in MATCH_FIELDS}
        # A known node ID also constrains its synthetic address.
        for node,address in (('source','source_ip'),('destination','destination_ip')):
            if p[node] in NODE_IPS and p[address]=='*':p[address]=NODE_IPS[p[node]]
        return p
    for i,high in enumerate(ordered):
        a=predicate(high)
        if a['protocol'] in ('TCP','ICMP'):
            warn(dict(kind='unsupported-offered-traffic',rule_id=high['id'],other_id=None,
                                 message='The live simulator offers UDP only; this protocol can be exercised in the read-only sandbox.'))
        for node,address in (('source','source_ip'),('destination','destination_ip')):
            if a[node] in NODE_IPS and a[address] not in ('*',NODE_IPS[a[node]]):
                warn(dict(kind='empty-match',rule_id=high['id'],other_id=None,
                                     message=f'{node} identity and synthetic IP contradict one another; this rule cannot match.'))
        if high['action'] in ('DROP','METER') and a['traffic'] in ('*','SAFETY') and a['protocol'] in ('*','UDP') and a['dst_port'] in (None,5005):
            warn(dict(kind='safety',rule_id=high['id'],other_id=None,
                                 message='This rule can suppress controller-bound safety delivery and delay M3 observations/recovery.'))
        for low in ordered[i+1:]:
            b=predicate(low)
            # IDs and equivalent IPs can overlap even when one side uses *.
            overlap=all(wildcard(a[k]) or wildcard(b[k]) or a[k]==b[k] for k in MATCH_FIELDS)
            if not overlap:continue
            same_action=(high['action'],high['rate_kbps'])==(low['action'],low['rate_kbps'])
            cover=all(wildcard(a[k]) or a[k]==b[k] for k in MATCH_FIELDS)
            kind='duplicate' if a==b and same_action else 'shadowed' if cover else 'overlap'
            conflict=not same_action
            warn(dict(kind=kind,rule_id=low['id'],other_id=high['id'],conflict=conflict,
                message=f"{high['id']} {'fully shadows' if cover else 'overlaps'} {low['id']}; "
                        f"{'different actions/rates conflict. ' if conflict else ''}Priority then rule ID selects one static rule; dynamic protection remains applicable."))
    if warning_count>256:
        warnings.append(dict(kind='limit',rule_id='*',other_id=None,
                             message=f'Showing 256 of {warning_count} warnings. Check an individual draft for focused analysis.'))
    return warnings
