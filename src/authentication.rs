
use core::fmt;
use std::{fs::{self, File, OpenOptions}, io::{self, Error, ErrorKind, Read, Write}};
use chrono::prelude::*;
use bcrypt::*;

use crate::pass_manager::rofi::{prompt_display, prompt_input, prompt_password, RofiError};
pub fn auth_manager() -> bool {
    let has_authenticated_today = match auth_check(){
        Ok(bool)=> bool,
        Err(e) => false, //The only error that can occur is not being able to read latest login
                         //information
    };
    let mut proper_authentication = false;
    if has_authenticated_today {
        return true;
    }
    else {
        proper_authentication = match authenticate() {
            Ok(bool) => bool,
            Err(e) => {
                prompt_display("Failed to authenticate!");
                panic!("failed to authenticate");
            }, //update this later
        }
    }
    if proper_authentication { add_login(Utc::now()); }
    else {
        prompt_display("Wrong password");
    }
    proper_authentication

}

pub fn auth_check()-> Result<bool, io::Error> {
    //auth_file is declared as mut because file reading require mutation
    //The way IO works is that a "File" maintains a cursor into the file
    //Changing that cursor, to read, mutates the variable. Therefore having
    //to use mut.
    //The file is still open as read only so no worries about data races.
    let mut auth_file = match File::open("authentication.txt") 
    {
        Ok(f) => f,
        Err(e) =>panic!("Something horrible happened to authentication.txt: {}",e),
    };
    let mut latest_login = String::new();
    match auth_file.read_to_string(&mut latest_login) {
        Ok(_) => (),
        Err(e) => return Err(Error::new(e.kind(), format!("Failed to retrieve the latest login because of: {}", e))),
    }

    if latest_login.len() == 0 {
        return Ok(false);
    }
    else if latest_login.len() < 10{
        panic!("Invalid input in authentication.txt");
    }

    let now = &Utc::now().to_string()[..10];
    Ok(now.eq(&latest_login[..10]))
}


pub fn add_login(today: DateTime<Utc>) -> Result<(), io::Error> {
    // Open the file for reading first
    let mut auth_file: String = String::new();

    let mut fi: File = match OpenOptions::new()
        .read(true)
        .open("authentication.txt") 
        {
            Ok(mut f) => {
                match f.read_to_string(&mut auth_file) {
                    Ok(_) => (),
                    Err(e) => match e.kind() {
                        ErrorKind::NotFound => panic!("File authentication.txt deleted while processing."),
                        _ => panic!("Couldn't read from authentication.txt because: {}", e),
                    },
                }
                f
            },
            Err(e) => return Err(Error::new(e.kind(), format!("Couldn't open authentication.txt because: {}", e))),
        };

    // Prepare the new content
    let mut formated = today.format("%Y-%m-%d").to_string();
    formated = formated + "\n" + auth_file.as_str();

    // Reopen the file for writing and truncating
    let mut fi: File = match OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open("authentication.txt") 
        {
            Ok(f) => f,
            Err(e) => return Err(Error::new(e.kind(), format!("Couldn't open authentication.txt for writing because: {}", e))),
        };
        
    // Write the new content
    match fi.write_all(formated.as_bytes()) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::new(e.kind(), format!("Couldn't write to authentication.txt because: {}", e))),
    }
}

pub fn authenticate() -> Result<bool, AuthError>{
    let mut pass:String =prompt_password("Please enter the daily password: ")?;
    Ok(verify(pass, "$2b$13$E9b/VBBbQKkQOBOfFyOYqOdNlhWpX/60WdrRPZ4tXnld9ToaUXJTa")?)
}
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    BcryptError(String),
    RofiError(String),
    Other(String),
}
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "The username and password provided were incorrect!"),
            AuthError::Other(e) => write!(f, "Some error occured in the authentication process due to: {}", e),
            AuthError::BcryptError(string) => write!(f, "Bcrypt error"),
            AuthError::RofiError(s) => write!(f, "Rofi Error: {}\n", s),
        }
    }
}
impl From<BcryptError> for AuthError {
    fn from(err: BcryptError) -> Self {
        AuthError::BcryptError(err.to_string())
    }
}
impl From<RofiError> for AuthError {
    fn from(value: RofiError) -> Self {
        AuthError::RofiError(format!("{}", value).to_string())
    }
}
#[cfg(test)]
mod authentication_test {

    use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, os::unix::fs};

    use chrono::{Datelike, Utc};

    use crate::authentication::{self, *};

    use super::*;
    macro_rules! with_file_restore {
        ($file_path:expr, $test_block:block) => {{
            use std::fs::{read_to_string, write};
            use std::io;

            // Backup the original file contents
            let original_content = match read_to_string($file_path) {
                Ok(content) => content,
                Err(e) => panic!("Failed to read the original file for backup: {}", e),
            };

            // Run the test block
            let result = (|| -> io::Result<()> {
                $test_block
                    Ok(())
            })();

            // Restore the original file contents
            match write($file_path, original_content) {
                Ok(_) => (),
                Err(e) => panic!("Failed to restore the original file: {}", e),
            };

            // Handle the result of the test block
            match result {
                Ok(_) => (),
                Err(e) => panic!("Test block failed: {}", e),
            }
        }};
    }


    ///tests whether or not authentication works properly, when there is an authentication.txt
    ///file and when there isn't.
    #[test]
    fn already_authenticated() {
        with_file_restore!("authentication.txt", {
            let _ = add_login(Utc::now());
            let result_2 = auth_check().unwrap();
            assert!(result_2);
        });
    }

    #[test]
    #[ignore] 
    fn bad_authentication() {
        with_file_restore!("authentication.txt", {
            // Test logic goes here
            let _ = add_login(Utc::now().with_day(15).unwrap());
            assert!(!auth_check().unwrap());
        });
    }
    #[test]
    #[ignore = "this test already passed and it takes time lol"]
    fn pass_check() {
        assert!(authenticate().unwrap());
    }
    #[test]
    #[ignore = "can't run it with the test below it"]
    fn first_auth_today() {
        with_file_restore!("authentication.txt",{
            if auth_check().unwrap() {
                let _fi: File = OpenOptions::new().truncate(true).open("authentication.txt").expect("Failed to truncate authentication.txt");
            }
            auth_manager();

        });

    }
    #[test]
    fn auth_manager_when_already_authenticated() {
        with_file_restore!("authentication.txt", {
            add_login(Utc::now());
            auth_manager();
        });
    }

}
