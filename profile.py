import geni.portal as portal
import geni.rspec.pg as pg

pc = portal.Context()
request = pc.makeRequestRSpec()
 
lan = pg.LAN()
request.addResource(lan)
prefixForIP = "192.168.1."
local_ip_count = 0

for i in range(3):
  node = request.XenVM("node-" + str(i))
  node.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops:UBUNTU16-64-STD"
  node.routable_control_ip = "true"
  local_ip_count += 1                    
  iface = node.addInterface("if" + str(local_ip_count))
  iface.component_id = "eth1"
  iface.addAddress(pg.IPv4Address(prefixForIP + str(local_ip_count), "255.255.255.0"))
  lan.addInterface(iface)
  node.addService(pg.Execute("sh", "sudo bash /local/repository/general.sh"))
 
# Print the RSpec to the enclosing page.
pc.printRequestRSpec(request)
