#![allow(dead_code)]

mod main_a {
    #[rocket::main]
    fn foo() { }

}

mod main_b {
    #[rocket::main]
    async fn foo() { }

}

mod main_d {
    #[rocket::main]
    fn main() {
        let _ = rocket::build().launch().await;
    }
}

mod main_f {
    #[rocket::main]
    async fn main() {
        rocket::build()
    }
}

// launch

mod launch_a {
    #[rocket::launch]
    async fn rocket() -> String {
        let _ = rocket::build().launch().await;
        rocket::build()

    }
}

mod launch_b {
    #[rocket::launch]
    async fn rocket() -> _ {
        let _ = rocket::build().launch().await;
        "hi".to_string()
    }
}

mod launch_c {
    #[rocket::launch]
    fn main() -> rocekt::Rocket<rocket::Build> {
        rocket::build()
    }
}

mod launch_d {
    #[rocket::launch]
    async fn rocket() {
        let _ = rocket::build().launch().await;
        rocket::build()
    }
}

mod launch_e {
    #[rocket::launch]
    fn rocket() {
        rocket::build()
    }
}

mod launch_f {
    #[rocket::launch]
    fn rocket() -> _ {
        let _ = rocket::build().launch().await;
        rocket::build()
    }
}

mod launch_g {
    #[rocket::launch]
    fn main() -> &'static str {
        let _ = rocket::build().launch().await;
        "hi"
    }
}

mod launch_h {
    #[rocket::launch]
    async fn main() -> _ {
        rocket::build()
    }
}

#[rocket::main]
async fn main() -> rocket::Rocket<rocket::Build> {
    rocket::build()
}
