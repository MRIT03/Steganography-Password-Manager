use std::{fs::{self, File, OpenOptions}, io::{self, Read, Write}, str::FromStr};
use bcrypt::{hash, hash_with_salt, verify};
use chrono::{prelude::*, Duration};
use rofi::{add_new_password, change_password, check_expirations_rofi, delete_password, gen_new_password, get_new_password, get_password, rofi_manager};
use watchful_deer::{authentication::*, pass_manager, run, };
use watchful_deer::pass_manager::*;
fn main(){ 
    run();
}


fn auth_check(latest_login:&str)-> bool {

    let now = &Utc::now().to_string()[..10];
    now.eq(latest_login)
}

