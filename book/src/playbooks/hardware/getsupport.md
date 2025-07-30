# On-site Support in Forge Managed Sites

Forge managed hardware is housed in both NVIDIA and Microsoft Azure operated datacenter locations.

## Azure

Forge operates in the following Azure collocation datacenters:

* AZ01, AZ02, AZ05 - San Jose, California (WUS)
* AZ03, AZ04, AZ06 - Wenatchee, Washington (WUS2)
* AZ[20..33] - Gavle, Sweden (SDC)
* AZ40, AZ41 - Toronto Canada (CNC)
* AZ50 - Tokyo, Japan (JPN)
* AZ51, AZ52 - Osaka Japan (JPW)
* AZ60, AZ61 - Frankfurt Germany (GWC)

More detail for these Microsoft Azure operated datacenters can be found on the
[Operations Management](https://confluence.nvidia.com/display/NSV/Operations+Management) Confluence page. This page
contains email addresses for the "site services" group for each datacenter which can be handy to use when getting
status of tickets or scheduling a work window. Take five minutes to read the details provided there.

### GDCO (Global DataCenter Operations)

The GDCO team are the "smart hands" for Azure colos. They are reponsible for the following tasks:

* Any work that requires physical manipulation of systems
  * Power cycle/drain
  * Changing/installation or reseating of parts
  * Replacing/reseating network or power cables
* Ordering parts that need to be replaced

The GDCO team will _not_ perform any of these tasks:

* Run complex diagnostic tasks
* Update firmware
* Install any software or utilities on hosts
* Interact with vendor support on any level

The process of getting access to GDCO and training on how to use it are available on the
[Microsoft GDCO Ticketing Process](https://confluence.nvidia.com/pages/viewpage.action?spaceKey=NSV&title=Microsoft+GDCO+ticketing+process)
Confluece page.

Tips for successful interactions with GDCO:

* Always provide "sufficient" detail in the case for the technician to easily grasp the task at hand. From experience,
  most technicians will not ask questions before attempting to work on the case and will close the ticket if they
  don't have enough instruction to complete the task at hand.
* Provide expected tasks and outcomes/results
* Ask for details to be added to the case nodes where appropriate. I.e., if replacing a motherboard include
  instructions to record the new MAC and IP address of the system.
* When replacing parts, request the ticket not be closed until the repair is verified.
* For complex tasks, issue the GDCO ticket and then email the site services team for the datacenter and request
  a work window. They will dedicate a technician to work on the system at the alloted time. The technician should
  make themselves available over chat while the work is ongoing. This is very helpful when dealing with issues
  that require some back and forth or when we have a customer system that has a very specific outage window. Turn
  around time is at least 24 hours in advance.
* Get to know the technicians at the various sites. It's a small group and its always easier to get a good
  response out of someone you have developed a repore with. They are people too :-) That said, if you have
  repeated bad experiences you should email [Jeremy Bamsch](mailto:Jeremy.Bamsch@microsoft.com) and report those. They are keen to
  provide feedback to technicians who may not be providing a good experience to their customers.

## NVIDIA Managed Sites

The [Datacenters/POPs/CSPs](https://confluence.nvidia.com/pages/viewpage.action?pageId=1272857365) Confluence page has
detailed information for Forge managed production sites including:

* [HFA - Haifa, Israel](https://confluence.nvidia.com/display/NGCGNI/HFA01)
* [TLV01 - Telaviv, Israel](https://confluence.nvidia.com/display/NGCGNI/TLV01)
* [TLV02 - Telaviv, Israel](https://confluence.nvidia.com/display/NGCGNI/TLV02)
* [PDX01 - Portland, OR](https://confluence.nvidia.com/display/NGCGNI/PDX01)
* [TPE01 - Taiwan](https://confluence.nvidia.com/display/NGCGNI/TPE01)

Getting support for these sites involves opening a [NVSH Jira ticket](https://jirasw.nvidia.com/browse/NSVH).

Technicians in these sites are more empowered to resolve issues on their own and generally do very good work.
They will also help you engage with equpiment vendors if need be.
