# Reliable state handling

Carbide achieves "reliable state handling" for a variety of resources via a mechanism called the "state controller".

"Reliable" state handling means the resources can traverse through their lifecycle states even in the case of intermittent errors (e.g. a Host BMC or a dependent service is temporarily unavailable) due to automated periodic retries. It also means that the state handling is deterministic and free of race conditions.

Resources managed by State Controllers are:
- ManagedHost Lifecycle
- IB Partition Lifecycle
- Network Segment Lifecycle

The following bullet-points summarize the functionality:
- Carbide defines some generic interfaces for resources whose state need to be handled. The [StateHandler interface](https://github.com/NVIDIA/carbide-core/blob/main/crates/api/src/state_controller/state_handler.rs) and the [IO interface](https://github.com/NVIDIA/carbide-core/blob/main/crates/api/src/state_controller/io.rs). The handler implementation specifies how to transition between states, while IO defines how to load resources from the database and store them back there.
- The state handling function needs to be implemented in an idempotent fashion, so that it can be retried in the case of failures.
- The state handler is the only entity that directly changes the lifecycle state of a resource. And the only way to transition to a new state is by the handler function returning the new state as result. Other components like API handlers are only allowed to queue intents/requests (e.g. "I want to use this host as an instance", "I want to report a network status change",  "I want to report a health status change"). That prevents lots of race conditions.
- For hosts/machines - Carbide biggest resource - [the implementation is here](https://github.com/NVIDIA/carbide-core-snapshot/blob/main/crates/api/src/state_controller/machine/handler.rs). As one can observe when diving down the functions, it's basically a gigantic switch/case ("if this state, then wait for this signal, and go to the next"). Modelling states as Rust enums immensely helps here. It's impossible to ignore handling a particular state or substate. The compiler would complain. Top level host lifecycle state is defined here - and as you can see its very big. The states also all serialize into JSON values, which can be observed in the state history with admin tooling for each resource.
- There's state diagrams in the docs: [architecture/state_machines/managedhost.html](architecture/state_machines/managedhost.html)
- Every time the state handler runs it also generates a set of metrics for every resource it manages. That for example provides visibility into "what resource is in what state", but also "how long does it take to exit a state, where does exiting the state fail due to failures, and resource specific metrics like "what is the health of hosts".
- Every state also has a SLA attached to it - a time in which we expect the resource to leave the state. That SLA is used to produce additional information in APIs ("is the resource in state for longer than SLA"), as well as in metrics and alerts (provides visibility into how many resources/hosts are stuck).

The execution of the state handlers is performed in the following fashion:
- The handler function scheduled for execution periodically (typically every 30s) in a way that guarantees that state handlers for differnt resources can run in parallel, but the state handler for the same resource is running at most once. The periodic execution guarantee that even if something fails intermittently, it will be automatically retried in the next iteration.
- If the state handling function of a state handler returns `Transition` (to the next state), then the state handler will be scheduled to run again immediately. This avoids the 30s wait time - which especially helps if the resource needs to go through a multiple small states which should all be retryable individually.
- In addition to periodic scheduling and scheduling on state transitions, carbide-core components can also explictily request the state handler for any given resource to re-run as soon as possible via the [Enqueuer](https://github.com/NVIDIA/carbide-core/blob/main/crates/api/src/state_controller/controller/enqueuer.rs) component. This allows to react as-fast-as-possible to external events, e.g. to a reboot notification from a host.
