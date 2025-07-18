import argparse
import boto3
import botocore
from configparser import ConfigParser
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, auto
from pathlib import Path
import os
import shutil
from typing import List, Optional, Dict, Any, Tuple
import getpass

class CommandResult:
    def __init__(self, success: bool, message: str, data: Any = None):
        self.success = success
        self.message = message
        self.data = data

    def __str__(self) -> str:
        return self.message

@dataclass
class AWSProfile:
    name: str
    arn: Optional[str] = None
    user_name: Optional[str] = None
    account_id: Optional[str] = None

class PasswordRequirement(Enum):
    MINIMUM_LENGTH = auto()
    SYMBOLS = auto()
    NUMBERS = auto()
    UPPERCASE = auto()
    LOWERCASE = auto()

class AWSAuth:
    def __init__(self):
        self.credentials_file = Path.home() / ".aws" / "credentials"

    def get_aws_profiles(self) -> List[str]:
        """Finds and returns all profiles from the AWS credentials file."""
        if not self.credentials_file.exists():
            return []

        parser = ConfigParser()
        parser.read(self.credentials_file)
        return parser.sections()

    def _create_session(self, profile_name: str) -> Tuple[Optional[boto3.Session], CommandResult]:
        """Creates a boto3 session for the given profile."""
        try:
            session = boto3.Session(profile_name=profile_name)
            return session, CommandResult(True, "")
        except botocore.exceptions.NoCredentialsError:
            return None, CommandResult(False, f"No credentials found for profile: {profile_name}")

    def _get_user_info(self, session: boto3.Session) -> Tuple[Optional[AWSProfile], CommandResult]:
        """Gets user information from AWS."""
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            arn = identity['Arn']

            if ':user/' not in arn:
                return None, CommandResult(False, "This tool only supports IAM users, not roles or root accounts.")

            user_name = arn.split('/')[-1]
            return AWSProfile(
                name=session.profile_name,
                arn=arn,
                user_name=user_name,
                account_id=identity['Account']
            ), CommandResult(True, "")
        except botocore.exceptions.ClientError as e:
            return None, CommandResult(False, f"AWS Error: {e.response['Error']['Message']}")

    def _format_status_output(self, password_last_used: Optional[datetime], keys: List[Dict]) -> str:
        """Formats the status output for a profile."""
        output = []

        if password_last_used:
            age = (datetime.now(UTC) - password_last_used).days
            output.append(f"    - Password Last Changed: {age} days ago ({password_last_used.strftime('%Y-%m-%d')})")
        else:
            output.append("    - Password Last Changed: Never or information not available.")

        if not keys:
            output.append("    - Access Keys:         No active access keys found.")
        for key in keys:
            key_id = key['AccessKeyId']
            create_date = key['CreateDate']
            key_age = (datetime.now(UTC) - create_date).days
            output.append(f"    - Access Key '{key_id}':")
            output.append(f"        - Age:            {key_age} days old (Created: {create_date.strftime('%Y-%m-%d')})")
            output.append(f"        - Status:         {key['Status']}")

        return "\n".join(output)

    def _backup_credentials(self) -> CommandResult:
        """Creates a backup of the credentials file."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        backup_file = f"{self.credentials_file}.bak-{timestamp}"
        try:
            shutil.copy(self.credentials_file, backup_file)
            if not os.path.exists(backup_file):
                return CommandResult(False, "Backup failed to create.")
            return CommandResult(True, f"Backed up credentials file to: {backup_file}")
        except (OSError, shutil.Error) as e:
            return CommandResult(False, f"Backup failed: {e}")

    def check(self, profile_name: str) -> CommandResult:
        """Check AWS profile health."""
        # Get credentials from the file for display, regardless of API call success
        parser = ConfigParser()
        parser.read(self.credentials_file)
        profile_credentials = {}
        if parser.has_section(profile_name):
            for key, value in parser.items(profile_name):
                if key in ['aws_access_key_id', 'aws_secret_access_key']:
                    profile_credentials[key] = value

        session, result = self._create_session(profile_name)
        if not result.success:
            # Return error with credentials data
            return CommandResult(False, result.message, data={"credentials": profile_credentials})

        user_info, result = self._get_user_info(session)
        if not result.success:
            # Return error with credentials data
            return CommandResult(False, result.message, data={"credentials": profile_credentials})

        output = [
            f"\n[+] Profile: {profile_name}",
            f"    - Status:         OK",
            f"    - Account ID:     {user_info.account_id}",
            f"    - User:           {user_info.arn}"
        ]
        return CommandResult(True, "\n".join(output), data={"credentials": profile_credentials, "user_info": user_info})

    def status(self, profile_name: str) -> CommandResult:
        """Get status of password and access keys."""
        session, result = self._create_session(profile_name)
        if not result.success:
            return result

        user_info, result = self._get_user_info(session)
        if not result.success:
            return result

        output = [f"\n[+] Getting status for profile: {profile_name}"]
        try:
            iam = session.client("iam")
            user = iam.get_user(UserName=user_info.user_name)
            password_last_used = user.get('User', {}).get('PasswordLastUsed')
            keys = iam.list_access_keys(UserName=user_info.user_name)['AccessKeyMetadata']

            output.append(self._format_status_output(password_last_used, keys))
            return CommandResult(True, "\n".join(output))
        except botocore.exceptions.ClientError as e:
            return CommandResult(False, f"AWS Error: {e.response['Error']['Message']}")

    def rotate_key(self, profile_name: str) -> CommandResult:
        """Rotates the access key for a given profile."""
        if not self.credentials_file.exists():
            return CommandResult(False, "Error: AWS credentials file not found at ~/.aws/credentials.")

        # Backup first
        backup_result = self._backup_credentials()
        if not backup_result.success:
            return backup_result

        output = [backup_result.message, f"\n[+] Rotating key for profile: {profile_name}"]

        session, result = self._create_session(profile_name)
        if not result.success:
            return result

        user_info, result = self._get_user_info(session)
        if not result.success:
            return result

        try:
            iam = session.client("iam")

            # List existing keys
            existing_keys = iam.list_access_keys(UserName=user_info.user_name)['AccessKeyMetadata']
            output.append("Existing access keys:")
            if not existing_keys:
                output.append("  No active access keys found.")
            for idx, key in enumerate(existing_keys, 1):
                create_date = key['CreateDate'].strftime("%Y-%m-%d %H:%M:%S")
                output.append(f"  {idx}. AccessKeyId: {key['AccessKeyId']}, Created: {create_date}, Status: {key['Status']}")

            confirmation = input("Proceed with creating a new key? (y/n): ")
            if confirmation.lower() != 'y':
                output.append("Rotation cancelled.")
                return CommandResult(True, "\n".join(output))  # Not failure, just cancelled

            # Create new access key
            new_key = iam.create_access_key(UserName=user_info.user_name)['AccessKey']
            new_access_key_id = new_key['AccessKeyId']
            new_secret_access_key = new_key['SecretAccessKey']
            output.append(f"    - Created new access key ID: {new_access_key_id}")

            # Update credentials file
            parser = ConfigParser()
            parser.read(self.credentials_file)
            if not parser.has_section(profile_name):
                parser.add_section(profile_name)
            parser.set(profile_name, 'aws_access_key_id', new_access_key_id)
            parser.set(profile_name, 'aws_secret_access_key', new_secret_access_key)
            with open(self.credentials_file, 'w', encoding='utf-8') as configfile:
                parser.write(configfile)
            output.append(f"    - Updated {self.credentials_file} with new key.")

            # Delete old keys interactively
            output.append("Select old keys to delete (comma-separated numbers, or 'all' to delete everything except new):")
            to_delete = input("> ").strip()
            if to_delete.lower() == 'all':
                for key in existing_keys:
                    if key['AccessKeyId'] != new_access_key_id:
                        iam.delete_access_key(AccessKeyId=key['AccessKeyId'], UserName=user_info.user_name)
                        output.append(f"    - Deleted old key: {key['AccessKeyId']}")
            else:
                try:
                    indices = [int(i.strip()) - 1 for i in to_delete.split(',') if i.strip().isdigit()]
                    for idx in indices:
                        if 0 <= idx < len(existing_keys):
                            key = existing_keys[idx]
                            if key['AccessKeyId'] != new_access_key_id:
                                iam.delete_access_key(AccessKeyId=key['AccessKeyId'], UserName=user_info.user_name)
                                output.append(f"    - Deleted key {idx+1}: {key['AccessKeyId']}")
                        else:
                            output.append(f"    - Warning: Invalid key number {idx+1} skipped.")
                except ValueError:
                    output.append("    - Invalid input for keys to delete. Skipping old key deletion.")

            output.append(f"Access key rotation for profile '{profile_name}' completed successfully.")
            return CommandResult(True, "\n".join(output))

        except botocore.exceptions.ClientError as e:
            return CommandResult(False, f"AWS Error: {e.response['Error']['Message']}")
        except Exception as e:
            return CommandResult(False, f"Unexpected error: {e}")

    def change_password(self, profile_name: str) -> CommandResult:
        """Changes the IAM user password for a given profile."""
        output = [f"\n[+] Changing password for profile: {profile_name}"]

        session, result = self._create_session(profile_name)
        if not result.success:
            return result

        user_info, result = self._get_user_info(session)
        if not result.success:
            return result

        try:
            iam = session.client("iam")

            # Get password policy
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
                output.append("AWS Account Password Policy:")
                if 'MinimumPasswordLength' in policy:
                    output.append(f"  - Minimum length: {policy['MinimumPasswordLength']}")
                if 'RequireSymbols' in policy and policy['RequireSymbols']:
                    output.append("  - Requires symbols")
                if 'RequireNumbers' in policy and policy['RequireNumbers']:
                    output.append("  - Requires numbers")
                if 'RequireUppercaseCharacters' in policy and policy['RequireUppercaseCharacters']:
                    output.append("  - Requires uppercase characters")
                if 'RequireLowercaseCharacters' in policy and policy['RequireLowercaseCharacters']:
                    output.append("  - Requires lowercase characters")
                if 'AllowUsersToChangePassword' in policy and policy['AllowUsersToChangePassword']:
                    output.append("  - Users are allowed to change their own password.")
                if 'MaxPasswordAge' in policy:
                    output.append(f"  - Maximum password age: {policy['MaxPasswordAge']} days")
                if 'PasswordReusePrevention' in policy:
                    output.append(f"  - Password reuse prevention: {policy['PasswordReusePrevention']} previous passwords")
            except iam.exceptions.NoSuchEntityException:
                policy = {}  # Default to no policy (AWS defaults apply)
                output.append("No custom password policy found for this account. Using AWS default.")

            while True:
                old_password = getpass.getpass("Enter your current password: ")
                new_password = getpass.getpass("Enter your new password: ")
                new_password_confirm = getpass.getpass("Confirm new password: ")

                if new_password != new_password_confirm:
                    output.append("Error: New passwords do not match. Please try again.")
                    continue

                # Validate against policy using enum for clarity
                if PasswordRequirement.MINIMUM_LENGTH.name.lower() in [r.name.lower() for r in PasswordRequirement] and 'MinimumPasswordLength' in policy and len(new_password) < policy['MinimumPasswordLength']:
                    output.append(f"Error: Password too short. Minimum length is {policy['MinimumPasswordLength']}. Please try again.")
                    continue
                if 'RequireSymbols' in policy and policy['RequireSymbols'] and not any(not c.isalnum() for c in new_password):
                    output.append("Error: Password must contain at least one symbol. Please try again.")
                    continue
                if 'RequireNumbers' in policy and policy['RequireNumbers'] and not any(c.isdigit() for c in new_password):
                    output.append("Error: Password must contain at least one number. Please try again.")
                    continue
                if 'RequireUppercaseCharacters' in policy and policy['RequireUppercaseCharacters'] and not any(c.isupper() for c in new_password):
                    output.append("Error: Password must contain at least one uppercase character. Please try again.")
                    continue
                if 'RequireLowercaseCharacters' in policy and policy['RequireLowercaseCharacters'] and not any(c.islower() for c in new_password):
                    output.append("Error: Password must contain at least one lowercase character. Please try again.")
                    continue
                
                try:
                    iam.change_password(OldPassword=old_password, NewPassword=new_password)
                    output.append("Password changed successfully!")
                    return CommandResult(True, "\n".join(output))
                except botocore.exceptions.ClientError as e:
                    output.append(f"Error: {e.response['Error']['Message']}. Please try again.")

        except botocore.exceptions.ClientError as e:
            return CommandResult(False, f"AWS Error: {e.response['Error']['Message']}")
        except Exception as e:
            return CommandResult(False, f"Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description=(
            "A CLI tool to manage AWS IAM user credentials.\n\n"
            "For more information on a specific command, use: awsauth <command> --help\n"
            "This will provide details on available options, including the --profile option."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common profile argument
    def add_profile_arg(p):
        p.add_argument(
            "--profile",
            type=str,
            default=None,
            help="AWS profile name (from ~/.aws/credentials). Use 'all' to operate on all profiles."
        )

    # check
    check_parser = subparsers.add_parser("check", help="Check AWS profile health.")
    add_profile_arg(check_parser)

    # status
    status_parser = subparsers.add_parser("status", help="Get status of password and access keys.")
    add_profile_arg(status_parser)

    # rotate-key
    rotate_parser = subparsers.add_parser("rotate-key", help="Rotate access key for a profile.")
    add_profile_arg(rotate_parser)

    # change-password
    pw_parser = subparsers.add_parser("change-password", help="Change IAM user password for a profile.")
    add_profile_arg(pw_parser)

    args = parser.parse_args()
    auth = AWSAuth()
    profiles = auth.get_aws_profiles()

    if args.command == "check":
        profile_arg = args.profile or "all"
        if profile_arg == "all":
            for profile in profiles:
                result = auth.check(profile)
                output_lines = [f"\n[+] Profile: {profile}"]
                if not result.success:
                    output_lines.append(f"    - Status:         ERROR")
                    output_lines.append(f"    - Error:          {result.message}")
                    output_lines.append(f"    - Account ID:     N/A")
                    output_lines.append(f"    - User:           N/A")
                else:
                    output_lines.append(f"    - Status:         OK")
                    if result.data and "user_info" in result.data:
                        output_lines.append(f"    - Account ID:     {result.data['user_info'].account_id}")
                        output_lines.append(f"    - User:           {result.data['user_info'].arn}")
                    else:
                        output_lines.append(f"    - Account ID:     N/A")
                        output_lines.append(f"    - User:           N/A")
                if result.data and "credentials" in result.data:
                    output_lines.append("    - Credentials:")
                    for key, value in result.data["credentials"].items():
                        output_lines.append(f"        - {key}: {value}")
                print("\n".join(output_lines))
        else:
            result = auth.check(profile_arg)
            output_lines = [f"\n[+] Profile: {profile_arg}"]
            if not result.success:
                output_lines.append(f"    - Status:         ERROR")
                output_lines.append(f"    - Error:          {result.message}")
                output_lines.append(f"    - Account ID:     N/A")
                output_lines.append(f"    - User:           N/A")
            else:
                output_lines.append(f"    - Status:         OK")
                if result.data and "user_info" in result.data:
                    output_lines.append(f"    - Account ID:     {result.data['user_info'].account_id}")
                    output_lines.append(f"    - User:           {result.data['user_info'].arn}")
                else:
                    output_lines.append(f"    - Account ID:     N/A")
                    output_lines.append(f"    - User:           N/A")
            if result.data and "credentials" in result.data:
                output_lines.append("    - Credentials:")
                for key, value in result.data["credentials"].items():
                    output_lines.append(f"        - {key}: {value}")
            print("\n".join(output_lines))
    elif args.command == "status":
        profile_arg = args.profile or "all"
        if profile_arg == "all":
            for profile in profiles:
                print(auth.status(profile))
        else:
            print(auth.status(profile_arg))
    elif args.command == "rotate-key":
        profile_arg = args.profile or "all"
        if profile_arg == "all":
            print("Warning: Rotating keys for all profiles will prompt interactively for each.")
            confirm = input(f"Proceed for {len(profiles)} profiles? (y/n): ")
            if confirm.lower() != 'y':
                print("Operation cancelled.")
                return
            for profile in profiles:
                print(auth.rotate_key(profile))
        else:
            print(auth.rotate_key(profile_arg))
    elif args.command == "change-password":
        profile_arg = args.profile or "all"
        if profile_arg == "all":
            print("Warning: Changing passwords for all profiles will prompt interactively for each.")
            confirm = input(f"Proceed for {len(profiles)} profiles? (y/n): ")
            if confirm.lower() != 'y':
                print("Operation cancelled.")
                return
            for profile in profiles:
                print(auth.change_password(profile))
        else:
            print(auth.change_password(profile_arg))

if __name__ == "__main__":
    main()