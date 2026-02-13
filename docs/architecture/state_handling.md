# Reliable State Handling

NVIDIA Bare Metal Manager (BMM) provides reliable state handling for a variety of resources via a mechanism called the *state controller*.

"Reliable state handling" refers to the ability of resources to traverse through lifecycle states even in the case of intermittent errors (e.g. a Host BMC or a dependent service is temporarily unavailable) via automated periodic retries. It also means that state handling is deterministic and free of race conditions.

These are the resources managed by the state controller:

- Managed Host Lifecycle
- IB Partition Lifecycle
- Network Segment Lifecycle
- Machine Lifecycle

The functionality of the state controller is described as follows:

- BMM defines some generic interfaces for resources that have states that need to be handled: the StateHandler interface and the IO interface. The handler implementation specifies how to transition between states, while IO defines how to load resources from the database and store them back there.
- The handler function is executed periodically (typically every 30s) and is implemented in an idempotent fashion, so, even if something fails intermittently, it will be automatically retried at the next iteration.
- The state handler is the only entity that directly changes the lifecycle state of a resource. And the only way to transition to a new state is by the handler function returning the new state as result. Other components like API handlers can only queue intents/requests (e.g. "Use this host as an instance", "Report a network status change",  "Report a health status change"), preventing many race conditions.
- For hosts/machines, the implementation is basically a single, large switch/case ("if this state, then wait for this signal, and go to the next"). Modelling states as Rust enums is immensely useful here. The compiler raises errors if a particular state or substate is not handled. The top level host lifecycle state is defined here, and it is very large. The states also all serialize into JSON values, which can be observed in the state history with admin tools for each resource.
- State diagrams are provided on the Managed Host State Diagrams page.
- Every time the state handler runs, it also generates a set of metrics for every resource it manages, providing visibility into what resource is in what state, how long it takes to exit a state, where exiting a state fails due to failures, as well as resource specific metrics like host health metrics.
- Every state also has an SLA attached to it--an expected time for the resource to leave the state. The SLA is used to produce additional information in APIs (for example, "is the resource in a particular state for longer than the SLA?"), as well as in metrics and alerts, providing visibility into how many resources/hosts are stuck.
