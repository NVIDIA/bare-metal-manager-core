use rocket::Route;
use rocket_dyn_templates::Template;

use super::ipxe::rpc::carbide_client::CarbideClient;
use ::rpc::v0 as rpc;

#[derive(serde::Serialize)]
pub struct BootInstructionGenerator<'a> {
    pub hostname: &'a str,
    pub kernel: String,
    pub initrd: String,
    pub command_line: String,
    pub state: &'a str,
}

#[get("/")]
pub async fn pxe() -> Template {
    let mut client = CarbideClient::connect("https://[::1]:1079").await.unwrap();
    let request = tonic::Request::new(rpc::MachineQuery {
        id: None,
        fqdn: "".to_string(),
    });

    let response = client.find_machines(request).await.unwrap();

    let machine = &response.into_inner().machines[0];
    let context = BootInstructionGenerator {
        hostname: &machine.fqdn,
        kernel: "vmlinuz".to_string(),
        initrd: "initrd".to_string(),
        state: &machine.state.as_ref().unwrap().state,
        command_line: "console=ttyS0,115200,8n1".to_string(),
    };

    Template::render("pxe", &context)
}

pub fn routes() -> Vec<Route> {
    routes![pxe]
}
