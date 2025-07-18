import pytest
from unittest.mock import patch, MagicMock
from botocore.stub import Stubber
import boto3
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os
import shutil
import getpass
from freezegun import freeze_time

# Import the AWSAuth class from your refactored code
from awsauth.main import AWSAuth, CommandResult, main

@pytest.fixture
def mock_home_dir(tmp_path):
    mock_home = tmp_path / "home" / "user"
    mock_home.mkdir(parents=True)
    
    # Create a mock .aws directory and credentials file
    mock_aws_dir = mock_home / ".aws"
    mock_aws_dir.mkdir()
    mock_credentials_file = mock_aws_dir / "credentials"
    mock_credentials_file.write_text(
        """
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[test-profile]
aws_access_key_id = AKIAIOSFODNN7TEST
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY
"""
    )
    
    with patch.object(Path, 'home', return_value=mock_home):
        yield mock_home

# Test for get_aws_profiles
def test_get_aws_profiles(mock_home_dir):
    auth = AWSAuth()
    profiles = auth.get_aws_profiles()
    assert "default" in profiles
    assert "test-profile" in profiles
    assert len(profiles) == 2

    # Test with no credentials file
    (mock_home_dir / ".aws" / "credentials").unlink()
    profiles = auth.get_aws_profiles()
    assert profiles == []

# Test for check method (single profile)
def test_check_single_profile(mock_home_dir):
    auth = AWSAuth()
    mock_sts = boto3.client('sts')
    with Stubber(mock_sts) as sts_stubber:
        sts_stubber.add_response(
            'get_caller_identity',
            {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:user/testuser'},
            {}
        )
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda service: mock_sts if service == 'sts' else MagicMock()
        with patch.object(boto3, 'Session', return_value=mock_session):
            result = auth.check("default")
            assert result.success
            assert "[+] Profile: default" in result.message
            assert "- Status:         OK" in result.message
            assert "- Account ID:     123456789012" in result.message
            assert "- User:           arn:aws:iam::123456789012:user/testuser" in result.message

# Test for check with multiple profiles (simulating "all")
def test_check_all_profiles(mock_home_dir):
    auth = AWSAuth()
    profiles = auth.get_aws_profiles()
    
    with patch.object(boto3, 'Session') as mock_session:
        mock_default_session = MagicMock(profile_name="default")
        mock_default_sts = boto3.client('sts')
        stubber_default = Stubber(mock_default_sts)
        stubber_default.add_response(
            'get_caller_identity',
            {'Account': '111111111111', 'Arn': 'arn:aws:iam::111111111111:user/defaultuser'},
            {}
        )
        mock_default_session.client.return_value = mock_default_sts
        
        mock_test_session = MagicMock(profile_name="test-profile")
        mock_test_sts = boto3.client('sts')
        stubber_test = Stubber(mock_test_sts)
        stubber_test.add_response(
            'get_caller_identity',
            {'Account': '222222222222', 'Arn': 'arn:aws:iam::222222222222:user/testuser'},
            {}
        )
        mock_test_session.client.return_value = mock_test_sts

        def session_side_effect(profile_name):
            if profile_name == "default":
                stubber_default.activate()
                return mock_default_session
            elif profile_name == "test-profile":
                stubber_test.activate()
                return mock_test_session
            else:
                raise ValueError(f"Unknown profile: {profile_name}")

        mock_session.side_effect = session_side_effect

        results = []
        for profile in profiles:
            results.append(auth.check(profile).message)

        combined_output = "\n".join(results)
        assert "[+] Profile: default" in combined_output
        assert "Account ID:     111111111111" in combined_output
        assert "[+] Profile: test-profile" in combined_output
        assert "Account ID:     222222222222" in combined_output

# Test for status method
@freeze_time('2025-07-18 10:00:00')
def test_status_method(mock_home_dir):
    auth = AWSAuth()
    with patch.object(boto3, 'Session') as mock_session:
        mock_iam = boto3.client('iam')
        iam_stubber = Stubber(mock_iam)
        iam_stubber.add_response(
            'get_user',
            {'User': {
                'Path': '/',
                'UserName': 'testuser',
                'UserId': 'AID1234567890EXAMPLE',
                'Arn': 'arn:aws:iam::123456789012:user/testuser',
                'CreateDate': datetime(2025, 7, 1, 10, 0, 0, tzinfo=timezone.utc),
                'PasswordLastUsed': datetime(2025, 7, 8, 10, 0, 0, tzinfo=timezone.utc)
            }},
            {'UserName': 'testuser'}
        )
        iam_stubber.add_response(
            'list_access_keys',
            {'AccessKeyMetadata': [{'AccessKeyId': 'AKIA1234567890ABCD', 'CreateDate': datetime(2025, 7, 13, 10, 0, 0, tzinfo=timezone.utc), 'Status': 'Active'}]},
            {'UserName': 'testuser'}
        )

        mock_sts = boto3.client('sts')
        sts_stubber = Stubber(mock_sts)
        sts_stubber.add_response(
            'get_caller_identity',
            {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:user/testuser'},
            {}
        )

        mock_sess = MagicMock()
        mock_sess.client.side_effect = lambda service: mock_iam if service == 'iam' else mock_sts
        mock_session.return_value = mock_sess

        iam_stubber.activate()
        sts_stubber.activate()

        result = auth.status("default")

        assert result.success
        assert "Getting status for profile: default" in result.message
        assert "Password Last Changed: 10 days ago (2025-07-08)" in result.message
        assert "Access Key 'AKIA1234567890ABCD'" in result.message
        assert "Age:            5 days old (Created: 2025-07-13)" in result.message
        assert "Status:         Active" in result.message

# Test for rotate_key method
def test_rotate_key_method(mock_home_dir):
    auth = AWSAuth()
    old_key_id = 'AKIAOLDKEYID12345678'
    new_key_id = 'AKIANEWKEYID12345678'

    with patch.object(boto3, 'Session') as mock_session:
        mock_iam = boto3.client('iam')
        iam_stubber = Stubber(mock_iam)
        iam_stubber.add_response(
            'list_access_keys',
            {'AccessKeyMetadata': [{'AccessKeyId': old_key_id, 'CreateDate': datetime.now(timezone.utc) - timedelta(days=10), 'Status': 'Active'}]},
            {'UserName': 'testuser'}
        )
        iam_stubber.add_response(
            'create_access_key',
            {'AccessKey': {
                'AccessKeyId': new_key_id,
                'SecretAccessKey': 'NEW_SECRET_KEY',
                'UserName': 'testuser',
                'Status': 'Active',
                'CreateDate': datetime.now(timezone.utc)
            }},
            {'UserName': 'testuser'}
        )
        iam_stubber.add_response(
            'delete_access_key',
            {},
            {'AccessKeyId': old_key_id, 'UserName': 'testuser'}
        )

        mock_sts = boto3.client('sts')
        sts_stubber = Stubber(mock_sts)
        sts_stubber.add_response(
            'get_caller_identity',
            {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:user/testuser'},
            {}
        )

        mock_sess = MagicMock()
        mock_sess.client.side_effect = lambda service: mock_iam if service == 'iam' else mock_sts
        mock_session.return_value = mock_sess

        iam_stubber.activate()
        sts_stubber.activate()

        with patch('builtins.input', side_effect=['y', 'all']):
            with patch('shutil.copy') as mock_copy:
                with patch('os.path.exists', return_value=True):
                    result = auth.rotate_key("default")

        assert result.success
        assert "Rotating key for profile: default" in result.message
        assert "Backed up credentials file to:" in result.message
        assert "Existing access keys:" in result.message
        assert "Created new access key ID:" in result.message
        assert "Updated" in result.message
        assert "Deleted old key:" in result.message
        assert "completed successfully" in result.message

# Test for change_password method
def test_change_password_method(mock_home_dir):
    auth = AWSAuth()

    with patch.object(boto3, 'Session') as mock_session:
        mock_iam = boto3.client('iam')
        iam_stubber = Stubber(mock_iam)
        iam_stubber.add_response(
            'get_account_password_policy',
            {'PasswordPolicy': {
                'MinimumPasswordLength': 12,
                'RequireSymbols': True,
                'RequireNumbers': True,
                'RequireUppercaseCharacters': True,
                'RequireLowercaseCharacters': True,
                'AllowUsersToChangePassword': True,
                'MaxPasswordAge': 90,
                'PasswordReusePrevention': 24
            }},
            {}
        )
        iam_stubber.add_response(
            'change_password',
            {},
            {'OldPassword': 'old_pass', 'NewPassword': 'NewPass123!@#'}
        )

        mock_sts = boto3.client('sts')
        sts_stubber = Stubber(mock_sts)
        sts_stubber.add_response(
            'get_caller_identity',
            {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:user/testuser'},
            {}
        )

        mock_sess = MagicMock()
        mock_sess.client.side_effect = lambda service: mock_iam if service == 'iam' else mock_sts
        mock_session.return_value = mock_sess

        iam_stubber.activate()
        sts_stubber.activate()

        with patch('getpass.getpass', side_effect=['old_pass', 'NewPass123!@#', 'NewPass123!@#']):
            result = auth.change_password("default")

        assert result.success
        assert "Changing password for profile: default" in result.message
        assert "AWS Account Password Policy:" in result.message
        assert "Minimum length: 12" in result.message
        assert "Requires symbols" in result.message
        assert "Requires numbers" in result.message
        assert "Requires uppercase characters" in result.message
        assert "Requires lowercase characters" in result.message
        assert "Users are allowed to change their own password." in result.message
        assert "Maximum password age: 90" in result.message
        assert "Password reuse prevention: 24" in result.message
        assert "Password changed successfully!" in result.message
