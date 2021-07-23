use crate::cfg;
use color_eyre::Report;
use carbide::protos;
use carbide::CarbideError;
use protos::carbide_server::Carbide;

use futures::TryFutureExt;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use tonic::{Code, Request, Response, Status};

#[derive(Debug)]
pub struct Api {
    database_pool: carbide::Pool,
    database_url: String, // Hack because bb8 and tokio-postgres wind up hiding the connection polling API
}

#[tonic::async_trait]
impl Carbide for Api {
    async fn get_machines(
        &self,
        _request: Request<protos::MachineQuery>,
    ) -> Result<Response<protos::MachineList>, Status> {
//        let x = self.database_pool
//            .get()
//            .map_err(|e| CarbideError::GenericError(String::from("foo") )
//            .and_then(|pool| pool.transaction().err_into() )
//            .and_then(|txn| carbide::models::Machine::find(&txn));
//
//        let y = x
//            .await
//            .map(protos::MachineList::from)
//            .map(Response::new);
//
        Ok(Response::new(protos::MachineList::from(vec![])))

        //.map(async |pool| pool.transaction().await
        //    .map(async |txn| carbide::models::Machine::find(&txn).await
        //        .map(protos::MachineList::from)
        //        .map(Response::new)
        //    )
        //).map_err(|err| Status::new(Code::Internal, err.to_string()))
    }

    //    type EventsStream = ReceiverStream<Result<protos::EventMessage, Status>>;
    //
    //    async fn events(
    //        &self,
    //        request: Request<protos::EventRequest>,
    //    ) -> Result<Response<Self::EventsStream>, Status> {
    //        info!("Got a request: {:?}", request);
    //
    //        let (client, connection) =
    //            match carbide::Datastore::direct_from_url(&self.database_url[..]).await {
    //                Ok(v) => v,
    //                Err(error) => return Err(Status::new(Code::Internal, error.to_string())),
    //            };
    //
    //        let (tx, rx) = mpsc::unbounded();
    //
    //        let stream =
    //            stream::poll_fn(move |cx| connection.poll_message(cx)).map_err(|e| panic!("{:?}", e));
    //
    //        let connection = stream.forward(tx).map(|r| r.unwrap());
    //
    //        tokio::spawn(connection);
    //
    //        let notifications = rx.filter_map(|m| match m {
    //            AsyncMessage::Notification(n) => future::ready(Some(n)),
    //            _ => future::ready(Node),
    //        });
    //
    //        //        tokio::spawn(async move {
    //        //            for number in numbers {
    //        //                let out_message = protos::EventMessage {
    //        //                    emitted: Some(SystemTime::now().into()),
    //        //                    event: Some(protos::event_message::Event::MachineAdded(
    //        //                        protos::EventMachineAdded {
    //        //                            id: Some(protos::Uuid {
    //        //                                value: number.to_string(),
    //        //                            }),
    //        //                        },
    //        //                    )),
    //        //                };
    //        //
    //        //                tx.send(Ok(out_message)).await.unwrap();
    //        //            }
    //        //        });
    //        //
    //        Ok(Response::new(ReceiverStream::new(rx)))
    //    }
}

impl Api {
    pub fn new(datastore: carbide::Pool, database_url: &str) -> Self {
        Self {
            database_pool: datastore,
            database_url: String::from(database_url),
        }
    }

    pub async fn run(
        service_config: &cfg::Service,
        api_config: &cfg::ApiService,
    ) -> Result<(), Report> {
        info!("Starting API server on {:?}", service_config.listen[0]);

        let api_service = Api::new(
            carbide::Datastore::pool_from_url(&api_config.datastore).await?,
            &api_config.datastore,
        );

        tonic::transport::Server::builder()
            .add_service(protos::carbide_server::CarbideServer::new(api_service))
            .serve(service_config.listen[0])
            .await?;

        Ok(())
    }
}
