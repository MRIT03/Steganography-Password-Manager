use std::{fmt, fs::{self, File, Metadata, OpenOptions}, io::{self, stdin, BufRead, BufReader, Error, Read, Write}, process::{Command, Output}, str::FromStr, usize};
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, TimeZone, Utc};
use rand::Rng;
use rofi::prompt_password;
use tempfile::tempfile;

static mut STEG_PASSWORD:String = String::new();
pub mod rofi;


#[derive(Clone)]
#[derive(Debug)]
pub struct PasswordEntry{
    pub app_name:String,
    app_url:String,
    pub username:String,
    pub picture:u8,
    pub expiration_day: DateTime<Utc>,
}

enum SecurityLevel {
    Alpha,
    Beta,
    Gamma,
    Delta,
}

#[derive(Debug)]
pub enum PassManagerError {
    IOError(std::io::Error),
    SteghideError(String),
    InvalidInput(String),

}

impl fmt::Display for PassManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IOError(e) => write!(f, "The PassManager Encountered an IO error, details: {}", e),
            Self::InvalidInput(message) => write!(f, "The PassManager Encountered an Invalid input, details: {}", message),
            Self::SteghideError(message) => write!(f, "The pass manager Encountered an error while using Steghide, details: {}", message),
        }
    }
}

impl std::error::Error for PassManagerError {

}
impl From<std::io::Error> for PassManagerError {
    fn from(value: std::io::Error) -> Self {
        PassManagerError::IOError(value)
    }
}

type Result<T> = std::result::Result<T, PassManagerError>;



#[derive(Debug)]
#[derive(PartialEq)]
pub struct Expirations {
    pub expired:Vec<String>,
    pub expiring_soon:Vec<String>,
}

impl SecurityLevel {
    fn generate_expiration_day(&self) -> DateTime<Utc>{
        let now = Utc::now();
        match &self {
            SecurityLevel::Alpha => now + Duration::days(90),
            SecurityLevel::Beta => now + Duration::days(120),
            SecurityLevel::Gamma => now + Duration::days(180),
            SecurityLevel::Delta => now + Duration::days(270),
        }
    }
    fn new(level:u8) -> Result<Self> {
        if level <0 || level >3 {
            return Err(PassManagerError::InvalidInput("Security Level value should be between 0 and 3 inclusive".to_string()));
        }
        match level {
            0 => Ok(SecurityLevel::Alpha),
            1 => Ok(SecurityLevel::Beta),
            2 => Ok(SecurityLevel::Gamma),
            3 => Ok(SecurityLevel::Delta),
            _ => Ok(SecurityLevel::Delta), // this will never be reached
        }
    } 
}

impl PasswordEntry {
    pub fn new_hardcoded(app_name:String, app_url:String, username:String, picture:u8, expiration_day:DateTime<Utc> ) -> Self {
        Self {
            app_name,
            app_url,
            username,
            picture, 
            expiration_day,
        }
    }
    fn new(app_name:String, app_url:String, username:String, sec_lvl:SecurityLevel ) -> Result<Self>{
        let picture = PasswordEntry::get_picture()?;
        Ok(PasswordEntry::new_hardcoded(app_name, app_url, username, picture, sec_lvl.generate_expiration_day()))
    }
    pub fn get_picture() -> Result<u8> {
        // Step 1: Open the file in read mode to read all lines
        let pic_file: File = OpenOptions::new().read(true).open("pictures")?;
        let reader = BufReader::new(&pic_file);

        // Step 2: Count the number of lines in the file
        let lines: Vec<String> = reader.lines()
            .map(|line| line.map_err(PassManagerError::IOError))
            .collect::<Result<Vec<String>>>()?;
        let line_count = lines.len();

        if line_count == 0 {
            return Err(PassManagerError::IOError(
                    io::Error::new(io::ErrorKind::InvalidInput, "All the pictures are currently allocated and the pic file is empty.")
            ));

        }

        // Step 3: Generate a random line number
        let mut random = rand::thread_rng();
        let line_number = random.gen_range(1..=line_count) - 1; // Convert to 0-based index

        // Step 4: Get the line to delete
        let pic_line = &lines[line_number];
        let output:String = pic_line.chars().filter(|c| c.is_digit(10)).collect();

        let output = output.parse().unwrap();
        println!("Selected line: {}", pic_line); // Optional: Just to see which line is selected

        // Step 5: Filter out the selected line
        let remaining_lines: Vec<String> = lines
            .into_iter()
            .enumerate()
            .filter(|(index, _)| *index != line_number)
            .map(|(_, line)| line)
            .collect();

        // Step 6: Open the file in write mode and truncate it (clear its contents)
        let mut pic_file = OpenOptions::new().write(true).truncate(true).open("pictures")?;

        // Step 7: Write the remaining lines back to the file
        for line in remaining_lines {
            writeln!(pic_file, "{}", line)?;
        }

        // Optional: Return some meaningful value or error, currently just returning Ok(1)
        Ok(output)
    }
    fn return_picture(&self)-> Result<()>{
        let mut fi = OpenOptions::new().write(true).append(true).open("pictures").unwrap();
        let pic_entry:String = self.picture.to_string() + ".jpeg\n";
        match fi.write(pic_entry.as_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => Err(PassManagerError::IOError(e)),
        }
    }
}
impl fmt::Display for PasswordEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}:{}:{}\n", self.app_name, self.app_url, self.username, self.picture, self.expiration_day.format("%d-%m-%Y"))
    }
}

impl FromStr for PasswordEntry {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let entry = s.split(':').collect::<Vec<&str>>();
        let format = "%d-%m-%Y";
        let naive_date:NaiveDate = NaiveDate::parse_from_str(entry[4], format).expect(&format!("failed to turn {}, into a DateTimeObj", entry[4]).to_string());
        let naive_datetime = naive_date.and_hms_opt(0, 0, 0).expect("Failure creating naive datetime from naive date");
        let exp_date:DateTime<Utc> = Utc.from_local_datetime(&naive_datetime).single().ok_or("Failed to convert string to utc")?;
        Ok(PasswordEntry::new_hardcoded(entry[0].to_string(), entry[1].to_string(), entry[2].to_string(), entry[3].parse().expect("failed to parse the image u8"),exp_date))
    }
}

pub fn store_entry(entry:PasswordEntry) -> Result<()> {
    let mut pass_file = OpenOptions::new().create(true).write(true).append(true).open("passwords")?;
    Ok(write!(pass_file,"{}", entry)?)
}

pub fn check_expirations() -> Result<Expirations>{
    let mut pass_file:File = OpenOptions::new().read(true).open("passwords")?;
    let reader = BufReader::new(&pass_file);
    let entries = reader.lines()
        .map(|line| line.map_err(PassManagerError::IOError))
        .collect::<Result<Vec<String>>>()?
        .into_iter()
        .map(|line| PasswordEntry::from_str(&line).expect(&format!("couldn't turn the following line into an entry: {}", line).to_string()))
        .collect::<Vec<PasswordEntry>>();
    let mut expired:Vec<String> = Vec::new();
    let mut expires_soon:Vec<String> = Vec::new();
    let now = Utc::now();
    for entry in entries {
        if entry.expiration_day < now {
            expired.push(format!("The password for {} with username {} has expired on the following date: {}\n\n", entry.app_name, entry.username, entry.expiration_day));
        }
        else if entry.expiration_day < now + Duration::days(7) {
            expires_soon.push(format!("The password for {} with username {} will expire soon on the following date: {}\n\n", entry.app_name, entry.username, entry.expiration_day));
        }  
    }
    Ok(Expirations {expired, expiring_soon:expires_soon })

}

fn generate_password(entry:PasswordEntry) -> Result<String> {
    let mut rng = rand::thread_rng();
    let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
        .chars()
        .collect();
    let between = rand::distributions::Uniform::from(0..charset.len());

    let random_string: String = (0..12)
        .map(|_| charset[rng.sample(between)])
        .collect();
    let _ = add_pass(entry, random_string.clone())?;
    Ok(random_string)
}
pub fn get_all_entries() -> Result<Vec<PasswordEntry>> {

    let mut read = OpenOptions::new().read(true).open("passwords")?;
    let buf_read  = BufReader::new(&read);
    let entries = buf_read.lines()
        .map(|line| line.map_err(PassManagerError::IOError))
        .collect::<Result<Vec<String>>>()?
        .into_iter()
        .filter_map(|line| match PasswordEntry::from_str(&line) {
            Ok(ent) => Some(ent),
            Err(s) => {
                println!("The following entry is invalid: {}", s);
                None
            }})
    .collect::<Vec<PasswordEntry>>();

    Ok(entries)
}
pub fn add_pass(mut entry:PasswordEntry, password:String) -> Result<()> {
    let entries =get_all_entries()?;

    let repitions = entries.clone()
        .into_iter()
        .filter(|file_entry| {
            file_entry.app_name == entry.app_name && file_entry.username == entry.username 
        })
    .collect::<Vec<PasswordEntry>>();
    
    if repitions.is_empty() {
        let _ = hide_pass(password, entry.picture)?;
        let _ =store_entry(entry)?;
        return Ok(());
    }

    for rep in repitions {
        rep.return_picture()?;
        entry.app_url = rep.app_url;
    }
    
    let non_repitions = entries.into_iter()
        .filter(|file_entry| {
            file_entry.app_name != entry.app_name || file_entry.username != entry.username 
        })
    .collect::<Vec<PasswordEntry>>();
    let mut write = OpenOptions::new().write(true).truncate(true).open("passwords")?;

    let mut out = String::new();
    for ent in non_repitions {
        out += &ent.to_string();
        println!("{}", out);
    }
    out += &entry.to_string();//this was done instead of store_entry as it is faster.
    let _ = hide_pass(password, entry.picture)?;
    write.write(out.as_bytes())?;


    Ok(())

}

fn delete_pass(entry: PasswordEntry) -> Result<()> {
    // Step 1: Read the current state of the file and store it
    let mut original_content = String::new();
    let mut file = File::open("passwords")?;
    file.read_to_string(&mut original_content)?;

    // Perform the deletion
    entry.return_picture();
    let read = get_all_entries()?;
    let mut out = String::new();
    for ent in read {
        if ent.app_name != entry.app_name || ent.username != entry.username {
            out += &ent.to_string();
        }
    }

    // Step 2: Write the new content to the file
    let mut write = OpenOptions::new().write(true).truncate(true).open("passwords")?;
    if let Err(e) = write.write(out.as_bytes()) {
        // Step 3: If writing fails, restore the original content
        let mut restore = OpenOptions::new().write(true).truncate(true).open("passwords")?;
        restore.write(original_content.as_bytes())?;
        return Err(PassManagerError::IOError(e));
    }

    // Step 4: Perform the final operations, and handle any errors
    match entry.return_picture() {
        Ok(_) => Ok(()),
        Err(e) => {
            // If this operation fails, you might want to log the error or handle it appropriately
            Err(e)
        }
    }
}
pub fn hide_pass(password:String, picture:u8) -> Result<()> {
    let mut tmp = OpenOptions::new().write(true).create(true).open("tmpfile")?;
    writeln!(tmp, "{}", password)?;
    let pic_dir = "/home/riad/Pictures/Harhour_and_chase/";
    let pass = get_steg_pass()?;
    let output:Output = Command::new("steghide")
        .arg("embed")
        .arg("-ef")
        .arg("./tmpfile")
        .arg("-cf")
        .arg(format!("{}{}.jpeg", pic_dir, picture))
        .arg("-p")
        .arg(pass)
        .output()?;

    match fs::remove_file("./tmpfile") {
        Ok(_) => (),
        Err(e) => return Err(PassManagerError::IOError(e)),
    }
    // Check if the command was successful
    if output.status.success() {
        // Print the stdout from the command
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Steghide command output: {}", stdout);
        return Ok(());
    } else {
        // Print the stderr from the command
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PassManagerError::SteghideError(stderr.to_string()));
    }
}

pub fn unhide_pass(entry: PasswordEntry)-> Result<String>{
    let pass = get_steg_pass()?;
    let pic_dir = "/home/riad/Pictures/Harhour_and_chase/";
    let output = Command::new("steghide")
        .arg("extract")
        .arg("-sf")
        .arg(format!("{}{}.jpeg", pic_dir, entry.picture))
        .arg("-p")
        .arg(pass)
        .output()?;
    if output.status.success() {
        // Print the stdout from the command
        //let stdout = String::from_utf8_lossy(&output.stdout);
        //println!("Steghide command output: {}", stdout);
        let output = get_data_from_temp()?;

        fs::remove_file("./tmpfile");
        return Ok(output);
    } else {
        // Print the stderr from the command
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PassManagerError::SteghideError(stderr.to_string()));
    }
}

pub fn get_steg_pass() -> Result<String>{
    unsafe {
        if !STEG_PASSWORD.is_empty() {
            return Ok(STEG_PASSWORD.clone());
        }
    }
    let pass = prompt_password("Session Password:").expect("WOOOPS");
    let output = Command::new("./src/encrypt_decrypt.sh")
        .arg("-d")
        .arg(pass)
        .output()?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        unsafe {
            STEG_PASSWORD = stdout.to_string().clone();
        }
        return Ok(stdout.to_string());
    }
    else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PassManagerError::SteghideError(stderr.to_string()));
    }
}

pub fn retrieve_pass(app_name:String, username:String) -> Result<String> {
    let entries = get_all_entries()?;
    let correct_entry = entries.iter().find(|entry| entry.app_name == app_name && entry.username == username);
    let correct_entry = match correct_entry {
        Some(pass) => pass.to_owned(),
        None => return Err(PassManagerError::InvalidInput(format!("No password entry for {} and {}", app_name, username))),
    };
    Ok(unhide_pass(correct_entry)?)
}


fn get_data_from_temp() -> Result<String>{
    let mut tmp = OpenOptions::new().read(true).open("./tmpfile")?;
    let mut buf = String::new();
    tmp.read_to_string(&mut buf)?;
    Ok(buf)
}


#[cfg(test)]
mod pass_manager_tests {
    use super::*;
    use crate::*; 
    #[test]
    fn pic_retrieval() {
        with_file_restore!("pictures", {
            let result = crate::pass_manager::PasswordEntry::get_picture();
            println!("{}", result.unwrap());
        });
    }

    #[test]
    #[ignore = "this test already proved it works"]
    fn pic_return() {
        //when writing the test, 27.jpeg was deleted.
        let shi = String::new();
        let pass = PasswordEntry::new_hardcoded(shi.clone(), shi.clone(), shi.clone(), 27, Utc::now());
        //PasswordEntry::return_picture(&pass).unwrap();
    }
    #[test]
    #[ignore = "leano hek"]
    fn store_password() {
        let entry:PasswordEntry = PasswordEntry::new_hardcoded("Google".to_string(), "www.google.com".to_string(),"Riadot03".to_string(), 8, Utc::now());
        let _ = store_entry(entry);
    }
    #[test]
    #[ignore = "ma khasak"]
    fn string_parsing() {
        let entry:PasswordEntry = PasswordEntry::new_hardcoded("Google".to_string(), "www.google.com".to_string(),"Riadot03".to_string(), 8, Utc::now());
        let parsed_entry = PasswordEntry::from_str("Google:www.google.com:Riadot03:8:11-08-2024").unwrap();
    }
    #[test]
    #[ignore = "data races"]
    fn check_expiration_test() {
        with_file_restore!("passwords", {
            let now = Utc::now();
            let dt_expired = NaiveDate::from_ymd_opt(1970, 1, 1)
                .unwrap()
                .and_hms_milli_opt(0, 0, 1, 444)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap();
            let dt_expires_less_than_week = Utc::now() +Duration::days(6);
            let dt_expires_in_exactly_a_week = Utc::now() +Duration::days(7);

            let dt_not_expiring_soon = Utc::now() +Duration::days(14);
            let dts = vec![dt_expired, dt_expires_less_than_week, dt_expires_in_exactly_a_week, dt_not_expiring_soon];
            for dt in dts {
                let entry = PasswordEntry::new_hardcoded("Google".to_string(), "www.google.com".to_string(),"Riadot03".to_string(), 8, dt);
                store_entry(entry).expect("failure storing entries");
            }
            let out1 = vec!["The password for Google with username Riadot03 has expired on the following date: 01-01-1970".to_string()];
            let out2 = vec!["The password for Google with username Riadot03 will expire on the following date: 16-08-2024".to_string(),
            "The password for Google with username Riadot03 will expire on the following date: 17-08-2024".to_string()];
            let corr_res = Expirations {expired:out1, expiring_soon:out2};
            let act_res = check_expirations().unwrap();
            assert_eq!(corr_res, act_res);
        });
    }
    #[test]
    fn remove_duplicates() {
        with_file_restore!("passwords", {
            let fi = OpenOptions::new().write(true).truncate(true).open("passwords")?;
            let mut vec:Vec<PasswordEntry> = Vec::new();
            vec.push(PasswordEntry::from_str("Google:www.google.com:Riadot03:8:15-08-2024").unwrap());
            vec.push(PasswordEntry::from_str("Google:www.google.com:Riadot03:3:15-08-2024").unwrap());
            vec.push(PasswordEntry::from_str("Google:www.google.com:Riad:7:15-08-2024").unwrap());
            vec.push(PasswordEntry::from_str("Facebook:www.google.com:Riadot03:21:15-08-2024").unwrap());
            vec.push(PasswordEntry::from_str("Facebook:www.google.com:Riad:2:15-08-2024").unwrap());
            vec.push(PasswordEntry::from_str("Facebook:www.google.com:Riadot03:1:15-08-2024").unwrap());
            for entry in vec.clone(){
                store_entry(entry);
            }
            add_pass(vec[1].clone(), "".to_string());
            add_pass(vec[3].clone(), "".to_string());

        })
    }
}

