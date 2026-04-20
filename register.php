<?php
session_start();
include 'koneksi.php';

$pesan = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // 1. Cek Konfirmasi Password Dulu
    if ($password !== $confirm_password) {
        $pesan = "<div class='error-msg'><i class='fa-solid fa-circle-exclamation'></i> Konfirmasi password tidak cocok!</div>";
    } else {
        // 2. Cek apakah Username atau Email sudah terdaftar
        $stmt_cek = $conn->prepare("SELECT uid FROM user WHERE uname = ? OR email = ?");
        $stmt_cek->bind_param("ss", $username, $email);
        $stmt_cek->execute();
        $stmt_cek->store_result();

        if ($stmt_cek->num_rows > 0) {
            $pesan = "<div class='error-msg'><i class='fa-solid fa-user-xmark'></i> Username atau Email sudah terdaftar!</div>";
        } else {
            // 3. Validasi Regex Server (Mutlak & Rahasia)
            $uppercase = preg_match('@[A-Z]@', $password);
            $lowercase = preg_match('@[a-z]@', $password);
            $number    = preg_match('@[0-9]@', $password);
            $special   = preg_match('@[^\w]@', $password);

            if (!$uppercase || !$lowercase || !$number || !$special || strlen($password) < 8) {
                $pesan = "<div class='error-msg'><i class='fa-solid fa-shield'></i> Password gagal memenuhi standar keamanan server!</div>";
            } else {
                // 4. BCRYPT HASHING
                $hashed_password = password_hash($password, PASSWORD_BCRYPT);

                // 5. Simpan ke DB (Tanpa masukin UID karena sudah Auto-Increment dari database)
                $stmt_insert = $conn->prepare("INSERT INTO user (uname, email, upassword) VALUES (?, ?, ?)");
                $stmt_insert->bind_param("sss", $username, $email, $hashed_password);

                if ($stmt_insert->execute()) {
                    echo "<script>alert('Registrasi Berhasil! Silakan Login.'); window.location='login.php';</script>";
                    exit();
                } else {
                    $pesan = "<div class='error-msg'>Gagal mendaftar. Silakan coba lagi.</div>";
                }
            }
        }
    }
}
?>

<!doctype html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Daftar - Velohertz</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { margin: 0; font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #e0f2fe 0%, #bae6fd 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; color: #0f172a; }
        .container { background: rgba(255, 255, 255, 0.6); backdrop-filter: blur(15px); padding: 40px; border-radius: 24px; box-shadow: 0 15px 35px rgba(0,0,0,0.05); width: 360px; text-align: center; border: 1px solid rgba(255,255,255,0.5); border-top: 5px solid #0f52ba; }
        h2 { font-size: 22px; margin-bottom: 20px; margin-top: 0; color: #0f52ba; }
        .input-group { margin-bottom: 15px; text-align: left; position: relative; }
        .input-group label { display: block; font-size: 13px; margin-bottom: 5px; font-weight: 600; }
        .input-group input { width: 100%; padding: 12px 15px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.5); background: rgba(255, 255, 255, 0.7); box-sizing: border-box; outline: none; transition: 0.3s; font-size: 14px; font-family: inherit; }
        .input-group input:focus { border-color: #0f52ba; background: #ffffff; }
        
        .password-wrapper { position: relative; }
        .toggle-password { position: absolute; right: 15px; top: 50%; transform: translateY(-50%); background: none; border: none; font-size: 18px; cursor: pointer; color: #475569; padding: 0; }
        
        .strength-meter { margin-top: 10px; padding: 12px; background: rgba(255,255,255,0.7); border-left: 4px solid #535353; border-radius: 8px; text-align: left;}
        .strength-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: white; margin-bottom: 5px; background: #535353;}
        .recommendation { font-size: 12px; color: #475569; line-height: 1.4; }

        .btn-submit { width: 100%; padding: 14px; background-color: #0f52ba; color: white; border: none; border-radius: 12px; font-weight: 600; font-size: 16px; cursor: pointer; transition: 0.3s; margin-top: 10px; }
        .btn-submit:hover { background-color: #0c4399; }
        .btn-submit:disabled { background-color: #94a3b8; cursor: not-allowed; }
        
        .error-msg { background: rgba(254,226,226,0.9); color: #e53e3e; font-size: 13px; padding: 12px; margin-bottom: 20px; border-radius: 8px; border: 1px solid #fecaca; text-align: left;}
        .login-link { display: block; font-size: 14px; color: #475569; text-decoration: none; margin-top: 15px; font-weight: 600; }
        .login-link:hover { color: #0f52ba; }
    </style>
</head>
<body>
    <div class="container">
        <h2><i class="fa-solid fa-user-plus"></i> Daftar Akun</h2>
        
        <?php echo $pesan; ?>

        <form action="" method="POST">
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" required placeholder="Pilih username" />
            </div>

            <div class="input-group">
                <label>Email</label>
                <input type="email" name="email" required placeholder="email@contoh.com" />
            </div>
            
            <div class="input-group">
                <label>Password</label>
                <div class="password-wrapper">
                    <input type="password" id="password" name="password" required placeholder="Buat password kuat" onkeyup="checkPasswordStrength()" />
                    <button type="button" class="toggle-password" onclick="toggleVisibility('password', 'eye-icon-pass')" id="eye-icon-pass">🙉</button>
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

            <button type="submit" name="register" id="btn-submit" class="btn-submit" disabled>Daftar Sekarang</button>
        </form>

        <a href="login.php" class="login-link">Sudah punya akun? Login di sini</a>
    </div>

    <script>
        function checkPasswordStrength() {
            const val = document.getElementById("password").value;
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
                strengthBadge.style.backgroundColor = "#535353";
                strengthBox.style.borderLeftColor = "#535353";
                recommendation.textContent = syaratMutlak;
                recommendation.style.color = "#475569";
                btnSubmit.disabled = true;
            } else if (strength < 4) {
                strengthBadge.textContent = "BELUM AMAN";
                strengthBadge.style.backgroundColor = "#e91429";
                strengthBox.style.borderLeftColor = "#e91429";
                recommendation.innerHTML = "<b>Password ditolak.</b> Pastikan memenuhi semua " + syaratMutlak;
                recommendation.style.color = "#e91429";
                btnSubmit.disabled = true; 
            } else if (strength === 4) {
                strengthBadge.textContent = "SANGAT KUAT";
                strengthBadge.style.backgroundColor = "#10b981";
                strengthBox.style.borderLeftColor = "#10b981";
                recommendation.textContent = "Sempurna! Password memenuhi standar keamanan.";
                recommendation.style.color = "#10b981";
                btnSubmit.disabled = false; 
            }
        }

        function toggleVisibility(inputId, iconId) {
            const input = document.getElementById(inputId);
            const icon = document.getElementById(iconId);
            if (input.type === "password") { 
                input.type = "text"; 
                icon.textContent = "🙈"; 
            } else { 
                input.type = "password"; 
                icon.textContent = "🙉"; 
            }
        }
    </script>
</body>
</html>