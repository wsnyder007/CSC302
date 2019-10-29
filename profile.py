import geni.portal as portal
import geni.rspec.pg as pg

pc = portal.Context()
request = pc.makeRequestRSpec()
 
# Add a raw PC to the request.
node = request.XenVM("node")
node.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops:UBUNTU16-64-STD"
node.routable_control_ip = "true"

#Install and execute a script 
node.addService(pg.Execute(shell="sh", command="sudo chmod 755 /local/repository/webserver.sh"))
node.addService(pg.Execute(shell="sh", command="/local/repository/webserver.sh"))

# Print the RSpec to the enclosing page.
pc.printRequestRSpec(request)
