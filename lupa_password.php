<?php
session_start();
include 'koneksi.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php'; 

$pesan = "";
$step = isset($_SESSION['reset_step']) ? $_SESSION['reset_step'] : 1;

if (isset($_POST['kirim_otp'])) {
    $email = trim($_POST['email']);
    
    $stmt = $conn->prepare("SELECT uid FROM user WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $otp = rand(100000, 999999);
        $_SESSION['reset_email'] = $email;
        $_SESSION['reset_otp'] = $otp;
        
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host       = 'smtp.gmail.com';
            $mail->SMTPAuth   = true;
            $mail->Username   = '';       // <-- Ganti email aslimu
            $mail->Password   = '';   // <-- Ganti 16 huruf App Password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            $mail->Port       = 465;

            $mail->setFrom('no-reply@velohertz.com', 'Velohertz Security');
            $mail->addAddress($email);

            $mail->isHTML(true);
            $mail->Subject = 'Kode OTP Reset Password Velohertz';
            $mail->Body    = "<h3>Permintaan Reset Password</h3>
                              <p>Kode OTP Anda adalah: <b style='font-size: 18px; letter-spacing: 2px;'>$otp</b></p>
                              <p>Jangan berikan kode ini kepada siapapun demi keamanan akun Anda.</p>";

            $mail->send();
            
            $_SESSION['reset_step'] = 2;
            $step = 2;
            $pesan = "<div class='success-msg'><i class='fa-solid fa-envelope'></i> Kode OTP telah dikirim ke email Anda!</div>";
        } catch (Exception $e) {
            $pesan = "<div class='error-msg'>Gagal mengirim email. Error: {$mail->ErrorInfo}</div>";
        }
    } else {
        $pesan = "<div class='error-msg'><i class='fa-solid fa-circle-exclamation'></i> Email tidak ditemukan di sistem!</div>";
    }
}

if (isset($_POST['verifikasi_otp'])) {
    $input_otp = trim($_POST['otp']);
    
    if ($input_otp == $_SESSION['reset_otp']) {
        $_SESSION['reset_step'] = 3;
        $step = 3;
        $pesan = "<div class='success-msg'><i class='fa-solid fa-unlock'></i> OTP Valid! Silakan buat password baru.</div>";
    } else {
        $pesan = "<div class='error-msg'><i class='fa-solid fa-xmark'></i> Kode OTP salah!</div>";
    }
}

if (isset($_POST['reset_password'])) {
    $new_pass = $_POST['new_password'];
    $confirm_pass = $_POST['confirm_password'];
    $email = $_SESSION['reset_email'];

    if ($new_pass !== $confirm_pass) {
        $pesan = "<div class='error-msg'><i class='fa-solid fa-circle-exclamation'></i> Konfirmasi password tidak cocok!</div>";
    } else {
        $uppercase = preg_match('@[A-Z]@', $new_pass);
        $lowercase = preg_match('@[a-z]@', $new_pass);
        $number    = preg_match('@[0-9]@', $new_pass);
        $special   = preg_match('@[^\w]@', $new_pass);

        if (!$uppercase || !$lowercase || !$number || !$special || strlen($new_pass) < 8) {
            $pesan = "<div class='error-msg'><i class='fa-solid fa-shield'></i> Password Terlalu Lemah atau gagal memenuhi standar keamanan server!</div>";
        } else {
            $hashed_password = password_hash($new_pass, PASSWORD_BCRYPT);
            
            $stmt_update = $conn->prepare("UPDATE user SET upassword = ? WHERE email = ?");
            $stmt_update->bind_param("ss", $hashed_password, $email);
            
            if ($stmt_update->execute()) {
                session_destroy();
                echo "<script>alert('Password berhasil diubah! Silakan Login.'); window.location='login.php';</script>";
                exit();
            } else {
                $pesan = "<div class='error-msg'>Gagal update database.</div>";
            }
        }
    }
}

if (isset($_GET['cancel'])) {
    session_destroy();
    header("Location: lupa_password.php");
    exit();
}
?>

<!doctype html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lupa Password - Velohertz</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@800&family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        :root {
            --primary: #74b9ff;
            --primary-grad: linear-gradient(135deg, #3b71ca 0%, #a29bfe 100%);
            --emerald: #00cec9;
            --danger: #ff6b81;
            --text-main: #ffffff;
            --text-muted: rgba(255, 255, 255, 0.5);
            --app-bg-color: #0b0f19;
            --glass-bg: rgba(20, 25, 35, 0.6);
            --glass-border: rgba(255, 255, 255, 0.08);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Poppins', sans-serif; 
            background-color: var(--app-bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(59, 113, 202, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(116, 185, 255, 0.1) 0px, transparent 50%);
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            color: var(--text-main); 
        }

        .container { 
            background: var(--glass-bg); 
            backdrop-filter: blur(20px); 
            -webkit-backdrop-filter: blur(20px);
            padding: 40px; 
            border-radius: 30px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.4); 
            width: 100%; 
            max-width: 400px; 
            text-align: center; 
            border: 1px solid var(--glass-border); 
        }

        h2 { 
            font-family: 'Outfit', sans-serif;
            font-size: 32px; 
            margin-bottom: 25px; 
            margin-top: 0; 
            background: var(--primary-grad);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -1px;
        }

        .subtitle { font-size: 14px; color: var(--text-muted); margin-bottom: 25px; line-height: 1.6; }

        .input-group { margin-bottom: 20px; text-align: left; position: relative; }
        .input-group label { display: block; font-size: 13px; margin-bottom: 8px; font-weight: 500; color: var(--text-muted); }
        
        .input-group input { 
            width: 100%; padding: 14px 18px; border-radius: 16px; 
            border: 1px solid rgba(255, 255, 255, 0.1); background: rgba(255, 255, 255, 0.03); 
            color: var(--text-main);
            outline: none; transition: 0.3s; font-size: 14px; font-family: inherit; 
        }
        .input-group input::placeholder { color: rgba(255, 255, 255, 0.3); }
        .input-group input:focus { 
            border-color: var(--primary); background: rgba(255, 255, 255, 0.08);
            box-shadow: 0 0 15px rgba(116, 185, 255, 0.1); 
        }
        
        .password-wrapper { position: relative; }
        .toggle-password { 
            position: absolute; right: 15px; top: 50%; transform: translateY(-50%); 
            background: none; border: none; font-size: 18px; cursor: pointer; color: var(--text-muted); opacity: 0.8; transition: 0.3s;
        }
        .toggle-password:hover { opacity: 1; transform: translateY(-50%) scale(1.1); }
        
        .strength-meter { 
            margin-top: 14px; padding: 15px; background: rgba(0, 0, 0, 0.2); 
            border-left: 4px solid rgba(255, 255, 255, 0.2); border-radius: 14px; text-align: left;
            transition: all 0.3s ease;
        }
        .strength-badge { 
            display: inline-block; padding: 4px 10px; border-radius: 8px; 
            font-size: 10px; font-weight: 700; color: white; margin-bottom: 8px; 
            background: rgba(255, 255, 255, 0.2); letter-spacing: 0.5px; text-transform: uppercase;
            transition: all 0.3s ease;
        }
        .recommendation { font-size: 12px; color: var(--text-muted); line-height: 1.5; }

        .btn-submit { 
            width: 100%; padding: 15px; background: var(--primary-grad); 
            color: white; border: none; border-radius: 16px; 
            font-weight: 600; font-size: 15px; cursor: pointer; 
            transition: 0.3s; margin-top: 10px; font-family: inherit; letter-spacing: 0.5px;
        }
        .btn-submit:hover:not(:disabled) { transform: translateY(-3px); box-shadow: 0 10px 20px rgba(162, 155, 254, 0.3); }
        .btn-submit:disabled { background: rgba(255, 255, 255, 0.1); color: rgba(255, 255, 255, 0.3); cursor: not-allowed; box-shadow: none; }
        
        .btn-cancel { 
            display: inline-block; font-size: 14px; color: var(--text-muted); 
            text-decoration: none; font-weight: 400; margin-top: 20px; transition: 0.3s;
        }
        .btn-cancel:hover { color: var(--danger); text-decoration: underline; }

        .error-msg { background: rgba(255, 71, 87, 0.1); color: var(--danger); font-size: 13px; padding: 15px; margin-bottom: 20px; border-radius: 16px; border: 1px solid rgba(255, 71, 87, 0.3); text-align: left; display: flex; align-items: center; gap: 10px; font-weight: 500; backdrop-filter: blur(5px);}
        .success-msg { background: rgba(0, 206, 201, 0.1); color: var(--emerald); font-size: 13px; padding: 15px; margin-bottom: 20px; border-radius: 16px; border: 1px solid rgba(0, 206, 201, 0.3); text-align: left; display: flex; align-items: center; gap: 10px; font-weight: 500; backdrop-filter: blur(5px);}
    </style>
</head>
<body>
    <div class="container">
        <h2><i class="fa-solid fa-shield-halved"></i> Pemulihan</h2>
        
        <?php echo $pesan; ?>

        <?php if ($step == 1): ?>
            <p class="subtitle">Masukkan email akun Anda. Kami akan mengirimkan 6-digit OTP ke email tersebut.</p>
            <form action="" method="POST">
                <div class="input-group">
                    <label>Email Terdaftar</label>
                    <input type="email" name="email" required placeholder="email@contoh.com" />
                </div>
                <button type="submit" name="kirim_otp" class="btn-submit">Kirim OTP Via Email</button>
            </form>
            <a href="login.php" class="btn-cancel">Kembali ke Login</a>

        <?php elseif ($step == 2): ?>
            <p class="subtitle">Masukkan OTP yang telah dikirim ke <br><strong style="color: var(--primary);"><?php echo $_SESSION['reset_email']; ?></strong></p>
            <form action="" method="POST">
                <div class="input-group">
                    <label>Kode OTP (6 Angka)</label>
                    <input type="number" name="otp" required placeholder="Contoh: 123456" style="text-align: center; font-size: 24px; letter-spacing: 8px; font-weight: 600;" />
                </div>
                <button type="submit" name="verifikasi_otp" class="btn-submit">Verifikasi OTP</button>
            </form>
            <a href="?cancel=true" class="btn-cancel">Ganti Email</a>

        <?php elseif ($step == 3): ?>
            <p class="subtitle">Buat password baru yang kuat dan aman.</p>
            <form action="" method="POST">
                
                <div class="input-group">
                    <label>Password Baru</label>
                    <div class="password-wrapper">
                        <input type="password" id="new_password" name="new_password" required placeholder="Buat password kuat" onkeyup="checkPasswordStrength()" />
                        <button type="button" class="toggle-password" onclick="toggleVisibility('new_password', 'eye-icon-new')" id="eye-icon-new">🙉</button>
                    </div>
                    
                    <div class="strength-meter" id="strengthBox">
                        <span class="strength-badge" id="strengthBadge">KOSONG</span>
                        <div class="recommendation" id="recommendation">Syarat wajib: Min. 8 Karakter, Huruf Besar, Angka, dan Simbol (!@#$).</div>
                    </div>
                </div>

                <div class="input-group">
                    <label>Konfirmasi Password</label>
                    <div class="password-wrapper">
                        <input type="password" id="confirm_password" name="confirm_password" required placeholder="Ketik ulang password" />
                        <button type="button" class="toggle-password" onclick="toggleVisibility('confirm_password', 'eye-icon-confirm')" id="eye-icon-confirm">🙉</button>
                    </div>
                </div>

                <button type="submit" name="reset_password" id="btn-submit" class="btn-submit" disabled>Simpan Password Baru</button>
            </form>
            <a href="?cancel=true" class="btn-cancel" style="color: var(--danger);">Batalkan Proses</a>
        <?php endif; ?>
    </div>

    <script>
        function checkPasswordStrength() {
            const val = document.getElementById("new_password").value;
            const strengthBadge = document.getElementById("strengthBadge");
            const strengthBox = document.getElementById("strengthBox");
            const recommendation = document.getElementById("recommendation");
            const btnSubmit = document.getElementById("btn-submit");

            let strength = 0;

            if (val.length >= 8) strength += 1; 
            if (val.match(/[A-Z]/)) strength += 1; 
            if (val.match(/[0-9]/)) strength += 1; 
            if (val.match(/[^a-zA-Z0-9]/)) strength += 1; 

            const syaratMutlak = "Syarat wajib: Min. 8 Karakter, Huruf Besar, Angka, dan Simbol (!@#$).";

            if (val.length === 0) {
                strengthBadge.textContent = "KOSONG";
                strengthBadge.style.backgroundColor = "rgba(255, 255, 255, 0.2)";
                strengthBox.style.borderLeftColor = "rgba(255, 255, 255, 0.2)";
                recommendation.textContent = syaratMutlak;
                recommendation.style.color = "rgba(255, 255, 255, 0.5)";
                btnSubmit.disabled = true;
            } else if (strength < 4) {
                strengthBadge.textContent = "BELUM AMAN";
                strengthBadge.style.backgroundColor = "#ff6b81";
                strengthBox.style.borderLeftColor = "#ff6b81";
                recommendation.innerHTML = "<b>Password ditolak.</b> Pastikan memenuhi semua " + syaratMutlak;
                recommendation.style.color = "#ff6b81";
                btnSubmit.disabled = true; 
            } else if (strength === 4) {
                strengthBadge.textContent = "SANGAT KUAT";
                strengthBadge.style.backgroundColor = "#00cec9";
                strengthBox.style.borderLeftColor = "#00cec9";
                recommendation.textContent = "Sempurna! Password memenuhi standar keamanan.";
                recommendation.style.color = "#00cec9";
                btnSubmit.disabled = false; 
            }
        }

        function toggleVisibility(inputId, iconId) {
            const input = document.getElementById(inputId);
            const icon = document.getElementById(iconId);
            if (input.type === "password") { input.type = "text"; icon.textContent = "🙈"; } 
            else { input.type = "password"; icon.textContent = "🙉"; }
        }
    </script>
</body>
</html>