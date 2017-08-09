CSRF=$(curl -s -c dvwa.cookie "10.0.10.101/dvwa/login.php" | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)
SESSIONID=$(grep PHPSESSID dvwa.cookie | awk -F ' ' '{print $7}')
curl -s -b dvwa.cookie -d "username=admin&password=password&user_token=${CSRF}&Login=Login" "10.0.10.101/dvwa/login.php"
sed -i 's/impossible/low/' dvwa.cookie

