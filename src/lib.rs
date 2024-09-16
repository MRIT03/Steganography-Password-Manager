#![allow(warnings)]

use std::error::Error;

use authentication::auth_manager;
use pass_manager::rofi::rofi_manager;

pub mod authentication;
pub mod pass_manager; 

#[macro_export]
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
pub fn run() -> Result<(), Box<dyn Error>> {
    if auth_manager() {

        rofi_manager()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
}
