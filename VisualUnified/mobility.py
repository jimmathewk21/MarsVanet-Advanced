"""Deterministic lane geometry and lightweight longitudinal driving model.

Canvas coordinates use metres approximately, y increases downward. This is a
teaching traffic model, not a calibrated microsimulator. Policy code is absent.
"""
from bisect import bisect_right
from dataclasses import dataclass
import math


LANE_OFFSET = 10.0
TURN_RADIUS = 14.0
ACCELERATION = 1.6  # m/s²
DECELERATION = 3.0
TURN_SPEED = 8.0
MIN_SPACING = 34.0  # centre spacing; accommodates oversized dashboard cars
SIGNALS = [(x, y) for x in (270, 840) for y in (170, 330, 520)]


def signal_green(x_axis, now):
    phase = now % 32
    return phase < 14 if x_axis else 16 <= phase < 30


class LaneRoute:
    """Offset orthogonal loop with sampled quadratic turns and arc-length lookup."""
    def __init__(self, centreline):
        corners = []
        for i, p in enumerate(centreline):
            before, after = centreline[i - 1], centreline[(i + 1) % len(centreline)]
            incoming = self.unit(before, p)
            outgoing = self.unit(p, after)
            # Right side of each directed road in screen coordinates.
            corners.append((p[0] - LANE_OFFSET * (incoming[1] + outgoing[1]),
                            p[1] + LANE_OFFSET * (incoming[0] + outgoing[0]), incoming, outgoing))
        self.points = []
        for x, y, incoming, outgoing in corners:
            a = (x - incoming[0] * TURN_RADIUS, y - incoming[1] * TURN_RADIUS)
            b = (x + outgoing[0] * TURN_RADIUS, y + outgoing[1] * TURN_RADIUS)
            for j in range(21):
                t = j / 20
                px = (1-t)**2*a[0] + 2*(1-t)*t*x + t*t*b[0]
                py = (1-t)**2*a[1] + 2*(1-t)*t*y + t*t*b[1]
                dx, dy = (1-t)*(x-a[0])+t*(b[0]-x), (1-t)*(y-a[1])+t*(b[1]-y)
                self.points.append((px, py, math.degrees(math.atan2(dy, dx)), 0 < j < 20))
        self.distances = [0.0]
        for a, b in zip(self.points, self.points[1:] + self.points[:1]):
            self.distances.append(self.distances[-1] + math.hypot(b[0]-a[0], b[1]-a[1]))
        self.length = self.distances[-1]

    @staticmethod
    def unit(a, b):
        length = math.hypot(b[0]-a[0], b[1]-a[1])
        return ((b[0]-a[0])/length, (b[1]-a[1])/length)

    def pose(self, progress):
        p = progress % self.length
        i = min(len(self.points)-1, bisect_right(self.distances, p)-1)
        a, b = self.points[i], self.points[(i+1) % len(self.points)]
        t = (p-self.distances[i]) / (self.distances[i+1]-self.distances[i])
        delta = (b[2]-a[2]+180) % 360 - 180
        return (a[0]+(b[0]-a[0])*t, a[1]+(b[1]-a[1])*t, a[2]+delta*t)

    def distance_to_turn(self, progress):
        p = progress % self.length
        candidates = [(d-p) % self.length for d, point in zip(self.distances, self.points) if point[3]]
        return min(candidates)


@dataclass
class DrivingPlan:
    speed: float  # km/h
    distance: float
    status: str
    committed_junction: tuple | None = None


def plan_vehicle(vehicle, vehicles, route, now, dt, seed):
    """Plan all cars against the same old snapshot; no iteration-order dependence."""
    speed = vehicle.speed / 3.6
    cruise = vehicle.cruise_speed / 3.6
    desired = cruise * (1 + .035 * math.sin(now*.13 + int(vehicle.id[1:])*1.7 + seed))
    status = 'cruising'
    hard_limit = float('inf')
    committed = vehicle.committed_junction
    if route.distance_to_turn(vehicle.progress) < 36:
        desired = min(desired, TURN_SPEED)
        status = 'turning'
    angle = math.radians(vehicle.angle)
    ux, uy = math.cos(angle), math.sin(angle)
    if committed and ((committed[0]-vehicle.x)*ux+(committed[1]-vehicle.y)*uy < -32
                      or math.hypot(committed[0]-vehicle.x,committed[1]-vehicle.y)>150):
        committed = None
    for other in vehicles:
        if other.id == vehicle.id or not other.mobility_active:
            continue
        dx, dy = other.x-vehicle.x, other.y-vehicle.y
        ahead, lateral = dx*ux+dy*uy, abs(-dx*uy+dy*ux)
        heading = abs((other.angle-vehicle.angle+180) % 360-180)
        if hasattr(route,'length') and other.route == vehicle.route:
            ahead=(other.progress-vehicle.progress) % route.length
            lateral,heading=0,0
        if ahead > 0 and lateral < 5 and heading < 20:
            gap = max(0, ahead-MIN_SPACING)
            safe_speed=max(0,math.sqrt((other.speed/3.6)**2+2*DECELERATION*gap)-DECELERATION*dt)
            following_speed=max(0,other.speed/3.6+(gap-1.2*speed)*.6)
            if min(safe_speed,following_speed) < desired:
                desired=min(desired,safe_speed,following_speed)
                hard_limit = min(hard_limit, gap)
                status = 'following'
    # Fixed-time teaching signals at the six central junctions; all-red phases
    # permit clearing. Stop lines sit before the crossing road, not on it.
    if abs(ux) > .98 or abs(uy) > .98:
        horizontal = abs(ux) > .98
        if not signal_green(horizontal, now):
            for x, y in SIGNALS:
                dx, dy = x-vehicle.x, y-vehicle.y
                ahead, lateral = dx*ux+dy*uy, abs(-dx*uy+dy*ux)
                remaining = ahead-24
                if -1e-6 <= remaining < 85 and lateral <= 12:
                    remaining=max(0,remaining)
                    late_change = (vehicle.movement not in ('slowing for junction','waiting at junction')
                                   and remaining < speed*speed/(2*DECELERATION)+speed*dt+2 and speed>1)
                    if committed == (x,y) or late_change:
                        committed=(x,y)
                        status='clearing junction'
                        continue  # Too close to stop safely when the phase changes.
                    desired = min(desired, max(0, math.sqrt(2*DECELERATION*remaining+(DECELERATION*dt)**2)-DECELERATION*dt))
                    hard_limit = min(hard_limit, remaining)
                    status = 'waiting at junction' if speed < .5 else 'slowing for junction'
    new_speed = max(0, min(speed+ACCELERATION*dt, max(speed-DECELERATION*dt, desired)))
    distance = min(new_speed*dt, hard_limit)
    return DrivingPlan(min(new_speed, distance/dt)*3.6, distance, status, committed)
