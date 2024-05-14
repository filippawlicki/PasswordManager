#!/bin/bash

LOGGED=0
# Set the password to decrypt the master password
DECRYPTPASS="dummy"
# Get the directory of the script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Path to store the flag indicating whether the master password has been set
MASTERPASSWORD_FILE="$SCRIPT_DIR/.master_password"
PASSWORD_FILE="$SCRIPT_DIR/.passwords"
TMP_PASS_DIR="$SCRIPT_DIR/tmp"
TMP_PASS_FILE="$TMP_PASS_DIR/encrypted_password"

# Global variables to store user data
name=""
username=""
password=""

# Function to encrypt password
encrypt_password() {
  local password="$1"
  local file="$2"
  echo -n "$password" | openssl aes-256-cbc -a -salt -pbkdf2 -out "$file" -pass pass:"$DECRYPTPASS"
}

# Function to decrypt password
decrypt_password() {
  local file="$1"
  openssl aes-256-cbc -d -a -pbkdf2 -pass pass:"$DECRYPTPASS" -in "$file"
}

store_encrypted_password() {
  local encrypted_password="$1"

  # Check if "tmp" directory exists, create if not
  if [ ! -d "$TMP_PASS_DIR" ]; then
    mkdir "$TMP_PASS_DIR" || { echo "Error: Failed to create 'tmp' directory."; return 1; }
  fi

  # Write encrypted password to temporary file with a newline character
  echo -n "$encrypted_password" > "$TMP_PASS_FILE" && echo >> "$TMP_PASS_FILE"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to write encrypted password to '$TMP_PASS_FILE'."
    return 1
  fi

  return 0
}




# Function to check if master password is set
check_master_password() {
  if [ ! -f "$MASTERPASSWORD_FILE" ]; then
    # If the file doesn't exist, it means this is the first time running the app
    create_master_password
  else
    # If the flag file exists, it means the master password has been set
    ask_master_password
  fi
}

# Function to create master password
create_master_password() {
  master_password=$(zenity --password --title="Create Master Password")
  if [ -n "$master_password" ]; then
    DECRYPTPASS="dummy" # Set the default decrypt password
    encrypt_password "$master_password" "$MASTERPASSWORD_FILE"
    DECRYPTPASS="$master_password" # Set the new decrypt password
  else
    if [ -z "$master_password" ]; then
      zenity --error --text="Master password cannot be empty."
      create_master_password
    fi
  fi
}

ask_master_password() {
  if [ ! -f "$MASTERPASSWORD_FILE" ]; then
    zenity --error --text="Master password not set. Please run the script again to set the master password."
    exit 1
  fi

  entered_password=$(zenity --password --title="Enter Master Password")
  
  # Check return code to determine if the user clicked "Cancel"
  if [ $? -ne 0 ]; then
    zenity --error --text="Operation canceled. Exiting..."
    exit 1
  fi

  DECRYPTPASS="dummy" # Set the default decrypt password

  decrypted_password=$(decrypt_password "$MASTERPASSWORD_FILE")
  
  # Check if the entered password matches the decrypted master password
  if [ "$decrypted_password" != "$entered_password" ]; then
    zenity --error --text="Incorrect master password."
    ask_master_password
  fi
  DECRYPTPASS="$decrypted_password" # Set the new decrypt password
}


decrypt_from_list() {
  # Get corresponding username and encrypted password using awk
  details=$(awk -F'|' -v name="$name" '$1 == name {print $2, $3}' "$PASSWORD_FILE")

  # Extract username and encrypted password
  username=$(echo "$details" | cut -d ' ' -f 1)
  encrypted_password=$(echo "$details" | cut -d ' ' -f 2)

  store_encrypted_password "$encrypted_password"

  # Decrypt the password
  password=$(decrypt_password "$TMP_PASS_FILE")

  rm -f $TMP_PASS_FILE
}

# Function to save new password
save_password() {
  # Get input from the user
  response=$(zenity --forms --title="Save New Password" --text="Enter details:" \
    --add-entry="Name:" \
    --add-entry="Username:" \
    --add-password="Password:")

  # Parse user input
  name=$(echo "$response" | awk -F'|' '{print $1}')
  username=$(echo "$response" | awk -F'|' '{print $2}')
  password=$(echo "$response" | awk -F'|' '{print $3}')

  # Encrypt the password
  password=$(echo -n "$password" | tr -d '\n\t ')
  password=$(echo -n "$password" | openssl aes-256-cbc -a -salt -pbkdf2 -pass pass:"$DECRYPTPASS")

  # Append to the password file
  echo -n -e "\n$name|$username|$password" >> "$PASSWORD_FILE"

  zenity --info --text="Password saved successfully."

  main_menu
}


# Function to get password
get_password() {
  # Get list of names from the password file
  names=$(cut -d '|' -f 1 "$PASSWORD_FILE")

  # Display list of names for selection
  name=$(zenity --list --title="Select Name" --text="Choose a name:" --column="Name" $names)

  # Check if user clicked "Cancel" or closed the dialog without selecting an option
  if [ -z "$name" ]; then
    zenity --info --title="No Option Selected" --text="You did not select any option."
    main_menu
    return
  fi

  decrypt_from_list

  # Display username and password with option to copy
  zenity --info --title="Credentials for $name" --text="Username: $username\nPassword: $password\n\nClick OK to copy password to clipboard." && echo -n "$password" | xclip -selection clipboard

  main_menu
}


# Function to update password
update_password() {
  # Get list of names from the password file
  names=$(cut -d '|' -f 1 "$PASSWORD_FILE")

  # Display list of names for selection
  name=$(zenity --list --title="Select Name" --text="Choose a name:" --column="Name" $names)

  # Check if user clicked "Cancel" or closed the dialog without selecting an option
  if [ -z "$name" ]; then
    zenity --info --title="No Option Selected" --text="You did not select any option."
    main_menu
    return
  fi

  # Decrypt details for selected entry
  decrypt_from_list

  # Prompt for field to update
  field=$(zenity --list --title="Update Password" --text="Choose the field to update:" --column="Field" "Name" "Username" "Password")

  case $field in
    ("Name")
      # Prompt for updated name
      new_value=$(zenity --entry --title="Update Name" --text="Enter updated name:" --entry-text="$name")
      ;;
    ("Username")
      # Prompt for updated username
      new_value=$(zenity --entry --title="Update Username" --text="Enter updated username:" --entry-text="$username")
      ;;
    ("Password")
      # Prompt for updated password
      new_value=$(zenity --entry --title="Update Password" --text="Enter updated password:" --entry-text="$password")
      ;;
    *)
      zenity --error --text="Invalid option."
      main_menu
      return
      ;;
  esac

  # Check if new_value is empty
  if [ -z "$new_value" ]; then
    zenity --info --title="Empty Field" --text="The field cannot be empty."
    main_menu
    return
  fi

  # Encrypt the new password if updating password field
  if [ "$field" == "Password" ]; then
    new_value=$(echo -n "$new_value" | openssl aes-256-cbc -a -salt -pbkdf2 -pass pass:"$DECRYPTPASS")
  else 
    # Encrypt the password
    password=$(echo -n "$password" | tr -d '\n\t ')
    password=$(echo -n "$password" | openssl aes-256-cbc -a -salt -pbkdf2 -pass pass:"$DECRYPTPASS")
  fi

  

  # Update the corresponding field in the password file
  sed -i "/^$name|/d" "$PASSWORD_FILE"
  case $field in
    ("Name")
      echo -n -e "\n$new_value|$username|$password" >> "$PASSWORD_FILE"
      ;;
    ("Username")
      echo -n -e "\n$name|$new_value|$password" >> "$PASSWORD_FILE"
      ;;
    ("Password")
      echo -n -e "\n$name|$username|$new_value" >> "$PASSWORD_FILE"
      ;;
  esac

  zenity --info --text="Field updated successfully."

  main_menu
}




# Function to delete password
delete_password() {
  # Get list of names from the password file
  names=$(cut -d '|' -f 1 "$PASSWORD_FILE")

  # Display list of names for selection
  name=$(zenity --list --title="Select Name" --text="Choose a name to delete:" --column="Name" $names)

  # Confirm deletion
  zenity --question --text="Are you sure you want to delete the password for $name?" && \
  sed -i "/^$name|/d" "$PASSWORD_FILE" && \
  zenity --info --text="Password for $name deleted successfully."

  main_menu
}


# Function to change master password
change_master_password() {
  # Ask for the current master password
  current_password=$(zenity --password --title="Enter your current master password:")
  
  # Check if the user clicked "Cancel"
  if [ -z "$current_password" ]; then
    main_menu
    return
  fi

  DECRYPTPASS="dummy" # Set the default decrypt password

  # Verify the entered password
  decrypted_password=$(decrypt_password "$MASTERPASSWORD_FILE")
  if [ "$decrypted_password" != "$current_password" ]; then
    zenity --error --text="Incorrect master password."
    main_menu
    return
  fi
  
  OLD_DECRYPTPASS="$decrypted_password" # Store the old decrypt password
  
  # If the password is correct, delete the encrypted master password file
  rm -f "$MASTERPASSWORD_FILE"

  # Run create_master_password to set a new master password
  create_master_password

  # Re-encrypt the password file with the new master password
  $NEW_PASSWORD_FILE="$SCRIPT_DIR/.new_passwords"
  if [ -f "$PASSWORD_FILE" ]; then
    while IFS= read -r line; do
      name=$(echo "$line" | cut -d '|' -f 1)
      username=$(echo "$line" | cut -d '|' -f 2)
      encrypted_password=$(echo "$line" | cut -d '|' -f 3)
      $password= openssl aes-256-cbc -d -a -pbkdf2 -pass pass:"$OLD_DECRYPTPASS" -in <(echo -n "$encrypted_password")
      password=$(echo -n "$password" | openssl aes-256-cbc -a -salt -pbkdf2 -pass pass:"$DECRYPTPASS")
      echo -n -e "\n$name|$username|$password" >> "$NEW_PASSWORD_FILE"
    done < "$PASSWORD_FILE"
  fi

  mv "$NEW_PASSWORD_FILE" "$PASSWORD_FILE"
  rm -f "$NEW_PASSWORD_FILE"

  zenity --info --text="Master password changed successfully."
  main_menu
}


# Function to generate new password
generate_new_password() {
  # Display dialog to get password generation options
  response=$(zenity --forms --title="Generate New Password" --text="Enter password generation options:" \
    --add-entry="Minimum Length:" \
    --add-entry="Maximum Length:" \
    --add-combo="Include capital letters:" --combo-values="yes|no" \
    --add-combo="Include special characters:" --combo-values="yes|no" \
    --add-combo="Include numbers:" --combo-values="yes|no")

  # Parse user input
  min_length=$(echo "$response" | awk -F'|' '{print $1}')
  max_length=$(echo "$response" | awk -F'|' '{print $2}')
  capital_letters=$(echo "$response" | awk -F'|' '{print $3}')
  special_characters=$(echo "$response" | awk -F'|' '{print $4}')
  numbers=$(echo "$response" | awk -F'|' '{print $5}')

  # Convert user input to lowercase
  capital_letters=$(echo "$capital_letters" | tr '[:upper:]' '[:lower:]')
  special_characters=$(echo "$special_characters" | tr '[:upper:]' '[:lower:]')
  numbers=$(echo "$numbers" | tr '[:upper:]' '[:lower:]')

  # Define character sets
  charset="abcdefghijklmnopqrstuvwxyz"
  if [ "$capital_letters" == "yes" ]; then
    charset+="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  fi
  if [ "$special_characters" == "yes" ]; then
    charset+="!@#$%^&*()_+-="
  fi
  if [ "$numbers" == "yes" ]; then
    charset+="0123456789"
  fi

  # Generate password based on user input
  generated_password=$(openssl rand -base64 1000 | tr -dc "$charset" | head -c $((min_length + RANDOM%(max_length-min_length+1))))
  if [ -z "$generated_password" ]; then
    zenity --error --text="Failed to generate password."
    main_menu
  fi

  # Display generated password with option to copy
  response=$(zenity --question --text="Generated Password:\n$generated_password\n\nDo you want to copy it to clipboard?")
  if [ "$?" -eq 0 ]; then
    echo -n "$generated_password" | xclip -selection clipboard
    zenity --info --text="Password copied to clipboard."
  fi

  main_menu
}

# Main menu
main_menu() {
  if [ "$LOGGED" -eq 0 ]; then
    check_master_password
  fi
  LOGGED=1
  choice=$(zenity --list --title="Password Manager Menu" --text="Select an option:" --column="Options" --height=275 --width=400 --hide-header "Save new password" "Get password" "Update password" "Delete password" "Change master password" "Generate new password" "Exit")
  
  case $choice in
    ("Save new password")
      save_password
      ;;
    ("Get password")
      get_password
      ;;
    ("Update password")
      update_password
      ;;
    ("Delete password")
      delete_password
      ;;
    ("Change master password")
      change_master_password
      ;;
    ("Generate new password")
      generate_new_password
      ;;
    ("Exit")
      exit 0
      ;;
    *)
      zenity --error --text="Invalid option"
      main_menu
      ;;
  esac
}

main_menu
