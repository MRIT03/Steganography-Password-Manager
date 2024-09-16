use std::{collections::HashSet, error::Error, fmt::write, process::{Command, Stdio}, str::FromStr};
use std::io::{self};
use super::*;
use crate::{pass_manager::{get_all_entries, PassManagerError, PasswordEntry}};
const ROFI_THEME:&str = "/home/riad/.config/rofi/styles/style_13.rasi";
type Result<T> = std::result::Result<T, RofiError>;


#[derive(Debug)]
#[derive()]
pub enum RofiError {
    IOError(std::io::Error),
    RofiCommandError(String),
    MenuParseError(String),
    PassManagerError(PassManagerError),
    InvalidInput(String),
    Error2,
}

impl std::error::Error for RofiError {}

impl std::fmt::Display for RofiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
       match self {
           RofiError::IOError(e) => write!(f, "- IO error, details: {}\n", e),
           RofiError::RofiCommandError(s) => write!(f, "- Rofi Outputted the following error: {}\n", s),
           RofiError::MenuParseError(s) => write!(f, "- Failed to parse the following menut item: {}\n", s),
           RofiError::InvalidInput(s) => write!(f, "- The following command generated invalid input: {}\n", s),
            _ => write!(f, "Will be written later..."),
       } 
    }
}

impl From<std::io::Error> for RofiError {
    fn from(value: std::io::Error) -> Self {
        return Self::IOError(value);        
    }
}
impl From<PassManagerError> for RofiError {
    fn from(value: PassManagerError) -> Self {
        return Self::PassManagerError(value);
    }
}

#[derive(Debug)]
pub enum MenuOptions {
    GeneratePassword,
    AddPassword,
    ChangePassword,
    DeletePassword,
    CheckExpirations,
    GetPassword,
    Exit,
}

// Implement the FromStr trait for MenuOptions
impl FromStr for MenuOptions {
    type Err = RofiError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Generate Password" => Ok(MenuOptions::GeneratePassword),
            "Add Password" => Ok(MenuOptions::AddPassword),
            "Change Existing Password" => Ok(MenuOptions::ChangePassword),
            "Delete Password" => Ok(MenuOptions::DeletePassword),
            "Check Expirations" => Ok(MenuOptions::CheckExpirations),
            "Retrieve Password" => Ok(MenuOptions::GetPassword),
            _ => Err(RofiError::MenuParseError(s.to_string())),
        }
    }
}
macro_rules! rofi_command {
    // The macro takes any number of arguments (additional args)
    ($($arg:expr),*) => {
        {
            // Create the base command
            let mut command = Command::new("rofi");
            command.arg("-theme").arg(ROFI_THEME);
            // Append additional arguments
            $(
                command.arg($arg);
            )*
            // Return the constructed command
            command
        }
    };
}

macro_rules! out_stat_debug {
    ($output:expr) => {
        if $output.status.success() {
            let stdout = String::from_utf8_lossy(&$output.stdout);
            print!("Rofi outputted: {}", stdout);
            Ok(stdout.to_string().trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&$output.stderr);
            print!("Rofi error: {}", stderr);
            Err(RofiError::RofiCommandError(format!("{}", stderr)))
        }
    };
}
macro_rules! out_stat {
    ($output:expr) => {
        if $output.status.success() {
            let stdout = String::from_utf8_lossy(&$output.stdout);
            Ok(stdout.to_string().trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&$output.stderr);
            Err(RofiError::RofiCommandError(format!("{}", stderr)))
        }
    };
}

fn basic_prompts() -> Result<PasswordEntry> {
    let app_name = match prompt_three_times("app name") {
        Ok(s) => s,
        Err(e) =>{
            prompt_display("Invalid username")?;
            return Err(e);
        }};
    let app_url =match prompt_three_times("app url"){
        Ok(s) => s,
        Err(e) => {
            prompt_display("Invalid app url")?;
            return Err(e);
        }
    };
    let username =match prompt_three_times("username"){
        Ok(s) => s,
        Err(e) => {
            prompt_display("Invalid username")?;
            return Err(e);
        }
    };
    let sec_level = prompt_security_level()?;
    let prompts = PasswordEntry::new(app_name, app_url, username, sec_level);
    
    Ok(prompts?)

}



pub fn prompt_password(text:&str) -> Result<String> {
    let output = rofi_command!("-password", "-dmenu", "-p",  text)
         .output()?;
    out_stat!(output)
}
pub fn prompt_input(input:&str) -> Result<String> {
    let output = rofi_command!( "-dmenu", "-p", input)
         .output()?;
    out_stat!(output)
}

pub fn prompt_display(input:&str) -> Result<String> {
    let output = rofi_command!( "-e", input)
         .output()?;
    out_stat!(output)
}

pub fn prompt_three_times(input:&str) -> Result<String> {
    let mut prompt_retries= 0;
    let elememt = loop {
        let result = prompt_input(&format!("Enter the {}: ", input));
        
        match result {
            Ok(s) => break s,
            Err(e) => {
                prompt_display(&format!("Invalid {}", input))?;
                if prompt_retries >= 2 {
                    prompt_display("you couldn't even input properly, you're a failure. Such a failure");
                    return Err(e);
                } else {
                    prompt_retries += 1;
                }
            }
        }
    };
    Ok(elememt)
}

fn prompt_security_level() -> Result<SecurityLevel> {
    let mut prompt_entries = 0;

    while prompt_entries < 3 {
        let sec_level_rofi = match prompt_input("security level (0-3):") {
            Ok(s) => s,
            Err(e) => {
                prompt_display("Invalid security level")?;
                return Err(e);
            }
        };

        match sec_level_rofi.trim().parse() {
            Ok(num) => match SecurityLevel::new(num) {
                Ok(level) => return Ok(level),
                Err(e) => {
                    prompt_entries += 1;
                    prompt_display("Invalid security level, please try again.")?;
                    if prompt_entries >= 3 {
                        return Err(RofiError::PassManagerError(e));
                    }
                }
            },
            Err(_) => {
                prompt_entries += 1;
                prompt_display("Invalid input, please enter a number.")?;
                if prompt_entries >= 3 {
                    return Err(RofiError::InvalidInput("Failed to parse security level".to_string()));
                }
            }
        };
    }

    Err(RofiError::InvalidInput("Exceeded maximum attempts".to_string()))
}



pub fn gen_menu(options:String, thing:&str) -> Result<String> {
    // Use Rofi to present the options and capture the user's selection
    let mut child = Command::new("rofi")
        .arg("-theme")
        .arg(ROFI_THEME) // Replace with your actual theme name or variable
        .arg("-dmenu")
        .arg("-p")
        .arg(&format!("Select {}:", thing))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    // Write the options to Rofi's stdin
    if let Some(mut stdin) = child.stdin.take() {
        std::io::Write::write_all(&mut stdin, options.as_bytes())?;
    }

    // Capture and process the user's selection
    let output = child.wait_with_output()?;
    let choice = String::from_utf8_lossy(&output.stdout);

    // Print the selected option or handle it accordingly
    println!("User selected: {}", choice.trim());

    Ok(choice.trim().to_string())
}

pub fn gen_options_menu() -> Result<MenuOptions> {
    // Define the options as a string, separated by newlines
    let options = "Retrieve Password\nGenerate Password\nAdd Password\nChange Existing Password\nDelete Password\nCheck Expirations\nExit\n";
    let rofi_out = gen_menu(options.to_string(), "an action")?;
    Ok(MenuOptions::from_str(&rofi_out)?)

}
pub fn gen_app_menu() -> Result<Vec<PasswordEntry>> {
    let mut options = String::new();
    let entries= get_all_entries()?;
    let mut set = HashSet::new();
    for entry in &entries {
        if set.contains(&entry.app_name){
            continue;
        }
        set.insert(&entry.app_name);
        options += &entry.app_name;
        options += "\n";
    }
    let rofi_out = gen_menu(options,"an app")?;
    let out:Vec<PasswordEntry> = entries.into_iter()
        .filter(|entry| entry.app_name == rofi_out)
        .collect::<Vec<PasswordEntry>>();
    println!("{:?}", out);
    Ok(out)
}

pub fn gen_username_menu(entries:Vec<PasswordEntry>) -> Result<PasswordEntry> {
    let mut options = String::new();
    for entry in &entries {
        options += &entry.username;
        options += "\n";
    }
    let rofi_out = gen_menu(options, "the username")?;
    println!("{}", rofi_out);
    let out = entries.into_iter().find(|entry| entry.username == rofi_out).expect("Zoinks how did this happen huhhhhh");
    Ok(out)
}

pub fn get_new_password() -> Result<Option<String>> {
    let mut password:PassManagerError = prompt_password("Please enter your password: ")?;
    let mut second_password = prompt_password("Please confirm your password: ")?;
    let mut prompts = 0;
    loop {
        if password == second_password {
            return Ok(Some(password));
        }
        else if prompts >=2 {
            return Ok(None);
        }
        else{
            prompts +=1;
            second_password = prompt_password("Passwords do not match, please try again:")?;
        }
    }

    Ok(None)

}

pub fn add_url() -> Result<String> {
    let url = prompt_input("Enter the URL: ")?;
    Ok(url)
}

pub fn gen_new_password() -> Result<()> {
    let entry = basic_prompts()?;
    let password = generate_password(entry)?;
    
    let out = Command::new("wl-copy").arg(&password).spawn()?;
    Ok(())
}

pub fn add_new_password() -> Result<()> {
    let entry = basic_prompts()?;
    let password = match  get_new_password()? {
        Some(s) => s,
        None => {
            prompt_display("password no bueno homeboy");
            return Err(RofiError::InvalidInput("Invalid password".to_string()));
        },
    };
    add_pass(entry, password)?;
    Ok(())
}


pub fn change_password() -> Result<()> {
    let app_name = gen_app_menu()?;
    let mut entry = gen_username_menu(app_name)?;
    let password = match  get_new_password()? {
        Some(s) => s,
        None => {
            prompt_display("password no bueno homeboy");
            return Err(RofiError::InvalidInput("Invalid password".to_string()));
        },
    };
    entry.return_picture();
    entry.picture = PasswordEntry::get_picture()?;
    add_pass(entry, password)?;
    Ok(())
}
pub fn delete_password() -> Result<()> {
    let app_name = gen_app_menu()?;
    let mut entry = gen_username_menu(app_name)?;
    delete_pass(entry)?;
    Ok(())
}

 
pub fn get_password() -> Result<()> {
    let app_name = gen_app_menu()?;
    let entry = gen_username_menu(app_name)?;
    let pass = unhide_pass(entry)?;
    let out = Command::new("wl-copy").arg(&pass).spawn()?;
    Ok(())
}

pub fn check_expirations_rofi() -> Result<()> {
   let exp = check_expirations()?;
   let mut expired = String::new();
   let mut expiring_soon = String::new();
   for entry in exp.expired {
       expired += &entry;
   }
   for entry in exp.expiring_soon {
       expiring_soon += &entry;
   }



   prompt_display(&expired)?;
   prompt_display(&expiring_soon)?;
   Ok(())
}

pub fn rofi_manager() -> Result<()> {
    loop {
        let action = gen_options_menu()?;
        match action {
            MenuOptions::GeneratePassword => gen_new_password()?,
            MenuOptions::AddPassword => add_new_password()?,
            MenuOptions::ChangePassword => change_password()?,
            MenuOptions::DeletePassword => delete_password()?,
            MenuOptions::GetPassword =>{
                get_password()?;
                break;
            },

            MenuOptions::CheckExpirations => check_expirations_rofi()?,
            MenuOptions::Exit => break,
        }
    }
    Ok(())
}





