<!DOCTYPE html>
<html lang="en">
  <head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>User Registration
	</title>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
  </head>
  <body>
	<div class="registration-container">
	  <div align="center" class="flex">
		<img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" id="inh1m">
	  </div>
	  <div class="header">
		<i class="fas fa-user-plus">
		</i>Enter Your Mobile Number
	  </div>
	  <!-- Error Message Block -->
	  [#if errorMessage?has_content]
	  <div role="alert" align="center" class="alert alert-danger mt-3 error">
		<p>${errorMessage} 
		</p>
	  </div>
	  [/#if]
	  <div class="content">
		<form method="post" enctype="application/x-www-form-urlencoded" id="registerForm">
		  <div class="form-group">
			<label class="form-label">Mobile Number: <span class="required">*</span></label>
			<input type="text" id="phoneNumber" name="phoneNumber" pattern="^\+?[1-9]\d{1,14}$" title="Enter a valid phone number (e.g., +1234567890" required="" placeholder="+1234567890" class="form-control">
		  </div>
		  <div class="buttons">
			<button type="submit" class="btn btn-primary">Submit</button>
			<button type="reset" id="cancel" name="cancel" value="cancel" class="btn btn-primary">Reset</button>
		  </div>
		  <!-- Hidden fields for context auto-fill -->
		  <input type="hidden" id="location" name="location" value="Unknown">
		  <input type="hidden" id="zone" name="zone" value="">
		  <input type="hidden" id="device" name="device" value="">
		</form>
	  </div>
	</div>
  </body>
  <style>
	body {
	  font-family: Arial, sans-serif;
	  background-color: #f8f9fa;
	  display: flex;
	  justify-content: center;
	  align-items: center;
	  height: 100vh;
	  margin: 0;
	}
	.flex{
	  padding: 10px;
	  margin-top: auto;
	}
	.registration-container {
	  width: 100%;
	  max-width: 600px;
	  background: white;
	  border-radius: 5px;
	  border: #080808;
	  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
	  overflow: hidden;
	}
	.header {
	  background: #28a745;
	  padding: 15px;
	  color: white;
	  font-size: 20px;
	  font-weight: bold;
	  display: flex;
	  align-items: center;
	}
	.header i {
	  margin-right: 10px;
	}
	.content {
	  padding: 20px;
	}
	.form-group {
	  margin-bottom: 15px;
	}
	.form-label {
	  font-weight: bold;
	  display: block;
	  margin-bottom: 5px;
	}
	.form-control {
	  width: 95%;
	  padding: 10px;
	  font-size: 14px;
	  border: 1px solid #ced4da;
	  border-radius: 5px;
	}
	.required {
	  color: red;
	}
	.error-message {
	  color: red;
	  font-size: 13px;
	  margin-top: 5px;
	}
	.error{
	  font-weight: bold;
	  color: red;
	}
	.buttons {
	  display: flex;
	  gap: 10px;
	}
	.btn {
	  padding: 10px 15px;
	  font-size: 16px;
	  border: none;
	  border-radius: 5px;
	  cursor: pointer;
	}
	.btn-primary {
	  background-color: #007bff;
	  color: white;
	}
	.btn-primary:hover {
	  background-color: #0056b3;
	}
	.btn-secondary {
	  background-color: #6c757d;
	  color: white;
	}
	.btn-secondary:hover {
	  background-color: #5a6268;
	}
	.login-link {
	  text-align: center;
	  margin-top: 10px;
	}
	.login-link a {
	  color: #007bff;
	  text-decoration: none;
	  font-weight: bold;
	}
	.login-link a:hover {
	  text-decoration: underline;
	}
  </style>
  <script>
	function validateForm(event) {
	  let password = document.getElementById("userPassword").value;
	  let confirmPassword = document.getElementById("confirmPassword").value;
	  let errorMessage = document.getElementById("error-message");
	  if (password !== confirmPassword) {
		errorMessage.innerText = "Passwords do not match!";
		return false;
	  }
	  errorMessage.innerText = "";
	  return true;
	}
	// Auto-fill time zone
	document.getElementById("zone").value = Intl.DateTimeFormat().resolvedOptions().timeZone;
	// Auto-fill device info
	const userAgent = navigator.userAgent;
	let device = "Unknown";
	if (userAgent.includes("Firefox")) device = "Firefox";
	else if (userAgent.includes("Chrome")) device = "Chrome";
	else if (userAgent.includes("Safari")) device = "Safari";
	else if (userAgent.includes("Edge")) device = "Edge";
	else if (userAgent.includes("Windows")) device = "Windows";
	else if (userAgent.includes("Linux")) device = "Linux";
	else if (userAgent.includes("Mac")) device = "Mac";
	document.getElementById("device").value = device;
	// Optional: location default as "Unknown"
	document.getElementById("location").value = "Web";
  </script>
</html>