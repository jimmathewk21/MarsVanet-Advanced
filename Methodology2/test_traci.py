import traci

traci.start(["sumo", "-n", "network.net.xml", "-r", "routes.rou.xml"])

while traci.simulation.getMinExpectedNumber() > 0:
    traci.simulationStep()

    for vehicle_id in traci.vehicle.getIDList():
        speed = traci.vehicle.getSpeed(vehicle_id)
        position = traci.vehicle.getPosition(vehicle_id)
        print(vehicle_id, "speed =", round(speed, 2), "position =", tuple(round(x, 2) for x in position))

traci.close()
