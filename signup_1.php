<?php

if(isset($_POST['signup']))
{
	include_once 'db_conn.php';

	$name = $_POST['name'];
    $gender = $_POST['gender'];
    $address = $_POST['address']
	$phonenumber = $_POST['phone'];
	$username = $_POST['user'];
	$password = $_POST['pwd'];
    $utype = $_POST['type']

	if(empty($name) || empty($gender) || empty($address) || empty($phonenumber) || empty($username) || empty($password))
	{
		header("Location: ../signup.php?error=emptyfields&name=".$name."&age=".$gender."&mail=".$address."&phone=".$phonenumber."&user=".$username);
		exit();
	}
	if(!preg_match("/^[a-zA-Z ]*$/", $name))
	{
		header("Location: ../signup.php?error=invalidname=".$name."&phone=".$phonenumber."&user=".$username);
		exit();

	}
	else if(!preg_match("/^[1-9]{1}[0-9]{6,10}$/", $phonenumber))
	{
		header("Location: ../signup.php?error=invalidphone&name=".$name."&user=".$username);
		exit();
	}
	else if(!preg_match("/^[a-zA-Z0-9]*$/", $username))
	{
		header("Location: ../signup.php?error=invalidusername&name=".$name."&phone=".$phonenumber);
		exit();
	}
	else if(!preg_match("/^([a-zA-Z0-9@*#]{8,15})$/", $password))
	{
		header("Location: ../signup.php?error=invalidpassword&name=".$name."&phone=".$phonenumber."&user=".$username);
		exit();
	}
	else
	{
		$sql = "SELECT UID FROM users WHERE UID = ?;";
		$stmt = mysqli_stmt_init($conn);
		if(!mysqli_stmt_prepare($stmt, $sql))
		{
			header("Location: ../signup.php?error=sqlerror");
			exit();	
		}
		else
		{
			mysqli_stmt_bind_param($stmt, "s", $username);
			mysqli_stmt_execute($stmt);
			mysqli_stmt_store_result($stmt);
			$resultCheck = mysqli_stmt_num_rows($stmt);
			if ($resultCheck > 0) {
				header("Location: ../signup.php?error=usernametaken&name=".$name."&phone=".$phonenumber);
				exit();
			}
			else
			{
				$sql = "INSERT INTO users (UID, pwd, utype, Name, Gender, address, MobileNo) VALUES (?, ?, ?, ?, ?, ?, ?);";
				$stmt = mysqli_stmt_init($conn);
				if(!mysqli_stmt_prepare($stmt, $sql))
				{
					header("Location: ../signup.php?error=sqlerror");
					exit();	
				}
				else
				{
					$hashedPwd = password_hash($password, PASSWORD_DEFAULT);
					mysqli_stmt_bind_param($stmt, "ssssssi", $username, $hashedPwd, $utype, $name, $gender, $address, $phonenumber);
					$result = mysqli_stmt_execute($stmt);
					if($result)
					{
						session_start();
					    $_SESSION['username'] = $username;
					}
					else
					{
						echo "<br>Error: ".$sql."<br>".mysqli_error($conn);
					}
					exit();
				}
			}
		}
	}
	mysqli_stmt_close($stmt);
	mysqli_close($conn);
}

?>