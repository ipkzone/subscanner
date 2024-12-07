<?php

error_reporting(0);
date_default_timezone_set('Asia/Jakarta');

$os = trim(PHP_OS);
if ($os == null) {
    die;
}
$identity = '';
$brand = '';

function GetInfo($opsys)
{
    switch ($opsys) {
        case 'WINNT':
            $uid = shell_exec('wmic csproduct get UUID');
            $uids = explode("\r\n", $uid);
            $uid = $uids[1];
            $vendor = shell_exec('wmic csproduct get Vendor');
            $vendor = explode("\r\n", $vendor);
            $vendors = $vendor[1];
            if (strlen($uid) > 0 && strlen($vendors) > 0) {
                return [md5($uid), $vendors];
            } else {
                echo 'Gagal Mendapatkan Informasi System : ' . $opsys;
                die;
            }
            break;

        case 'Linux':
            ob_start(); // mendapatkan detail ipconfing menggunakan CMD
            system('getprop'); // mendapatkan output kedalam variable
            $mycom = ob_get_contents(); // membersihkan output buffer
            ob_clean();
            ob_end_flush();

            $key = [];
            $val = [];
            $data = explode("\n", $mycom);

            foreach ($data as $d) {
                $perbaris = explode(':', $d);
                $key[] = $perbaris[0];
                $val[] = isset($perbaris[1]) ? $perbaris[1] : 'kosong';
            }

            $gabungan = array_combine($key, $val);
            if (strlen($gabungan['[ro.build.fingerprint]']) > 0 && strlen($gabungan['[ro.product.brand]']) > 0) {
                return [trim(md5($gabungan['[ro.build.fingerprint]'])), trim($gabungan['[ro.product.brand]'])];
            } else {
                echo 'Gagal Mendapatkan Informasi System : ' . $opsys;
                die;
            }
            break;

        default:
            echo 'Operating System Not SUpported : ' . $opsys;
            die;
    }
}

function datasender($url, $data)
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt(
        $ch,
        CURLOPT_HTTPHEADER,
        array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data),
        )
    );
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

function logins($akses, $ident, $vend, $type, $now)
{
    $url = 'serveripkzone.site/public/Api/login';
    $data = [
        'token' => $akses,
        'uid' => $ident,
        'brand' => $vend,
        'type' => $type,
        'now' => $now,
    ];
    $data = json_encode($data);
    $login = datasender($url, $data);
    if (strlen($login) > 0 && isValidJSON($login)) {
        $login = json_decode($login, true);
        $Yellow = "\e[33m";
        $Green = "\e[92m";
        $White = "\e[0m";
        $Red = "\e[31m";
        if ($login['state'] != 'Success' && $login['code'] != 101) {
            echo " {$Green}➤{$White} {$Red}OFFLINE{$White}\n";
            die;
        } elseif ($login['state'] == 'Success' && $login['code'] == 101) {
            $bearer = $login['bearer'];
            $user = $login['user'];
            echo " {$Green}➤{$White} [{$Green}ONLINE{$White}] | {$Green}{$user['username']}{$White} \n";

            return [$bearer, $user];
        }
    } else {
        echo $login;
        die;
    }
}

function isValidJSON($str)
{
    json_decode($str);
    return json_last_error() == JSON_ERROR_NONE;
}

function logger($auth, $akses, $data)
{
    $url = 'serveripkzone.site/public/Api/log';
    $data = [
        'id' => $akses,
        'aktifitas' => $data,
    ];
    $data = json_encode($data);

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt(
        $ch,
        CURLOPT_HTTPHEADER,
        array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data),
            'Authorization: Bearer ' . $auth,
        )
    );
    $result = curl_exec($ch);

    curl_close($ch);

    return $result;
}

$Yellow = "\e[33m";
$Green = "\e[92m";
$White = "\e[0m";

// getIPaddress
$getIP = file_get_contents('https://httpbin.org/ip');
$json = json_decode($getIP, true);
$ipAddres = $json['origin'];

list($identity, $brand) = GetInfo($os);

// ///STARTING VALIDATOR
$Yellow = "\e[33m";
$Green = "\e[92m";
$White = "\e[0m";
$Red = "\e[31m";
echo "\n {$Green}➤{$White} IPaddress: {$Yellow}$ipAddres{$White} | {$Red}This script requires license key access.{$White}\n";

$file = 'config.json';
$data = file_get_contents($file);
$obj = json_decode($data);
$licensi = $obj->licensikey;

$now = date('Y-m-d');
$tipebot = 'POINTKU';
list($bearer, $user) = logins($licensi, $identity, $brand, $tipebot, $now);

$Yellow = "\e[33m";
$Green = "\e[92m";
$White = "\e[0m";
$Red = "\e[31m";

$logger = [
    'type' => 'POINTKU',
    'brand' => $brand,
];

// SEND LOG
$send = logger($bearer, $user['id'], $logger);
$valid = IsValidJSON($send);
if (!$valid) {
}

$send = json_decode($send, true);

if ($send['code'] != 101) {
    die;
} else {
    // echo "Logging Status : " . $send["status"] . "\n";
}

$autoloadPath = __DIR__ . '/vendor/autoload.php';
$composerJsonPath = __DIR__ . '/composer.json';

function installDependencies($composerJsonPath) {
    if (!file_exists($composerJsonPath)) {
        die("File composer.json tidak ditemukan. Pastikan Anda berada di direktori proyek yang benar.\n");
    }

    echo "Dependensi belum ditemukan. Melakukan instalasi dengan Composer...\n";
    $output = null;
    $resultCode = null;
    exec('composer install', $output, $resultCode);

    if ($resultCode !== 0) {
        die("Gagal menjalankan 'composer install'. Pastikan Composer terinstal dan dapat diakses.\n");
    }

    echo "Dependensi berhasil diinstal.\n";
}
if (!file_exists($autoloadPath)) {
    installDependencies($composerJsonPath);
}

require $autoloadPath;

function checkClassExists($className) {
    if (!class_exists($className)) {
        die("Kelas '$className' tidak ditemukan. Pastikan library yang sesuai telah terinstal.\n");
    }
}

checkClassExists('TelegramBot\Api\BotApi');
checkClassExists('GuzzleHttp\Client');

use TelegramBot\Api\BotApi;
use GuzzleHttp\Client;


// error_reporting(0);
const n = "\n";
const r = "\r";
const kuning = "\e[1;93m";
const ungu = "\e[1;93m";
const putih = "\e[1;97m";
const biru = "\e[1;96m";
const birugelap = "\e[1;93m";
const hijau = "\e[1;92m";
const merah = "\e[1;91m";
const hitam = "\e[1;30m";
const blokb = "\e[1;104m";
const blokm = "\e[1;101m";
const blokp = "\e[1;107m";
const blokbi = "\e[1;105m";
const sp = ' ';
const spp = '   ';
const netral = "\e[0m";
const orange = "\e[38;5;214m";
define('garis', str_repeat('━', 60));

class SignatureService
{
    public static function signature($phone, $body)
    {
        idant:
        $curl = curl_init();
        $hash = md5('ipkzone1337');
        curl_setopt_array($curl, [
            CURLOPT_URL => "https://serveripkzone.site/pointku/_.php",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "POST",
            CURLOPT_POSTFIELDS => json_encode([
                'phone' => $phone, 
                'body' => $body,   
            ]),
            CURLOPT_HTTPHEADER => [
                "Accept: /",
                "Content-Type: application/json",
                "Authorization: Bearer $hash",
                "User-Agent: Thunder Client (https://www.thunderclient.com)",
            ],
        ]);

        $response = curl_exec($curl);

        if (curl_errno($curl)) {
            $error_message = curl_error($curl);
            curl_close($curl);
            goto idant;
        }

        curl_close($curl);
        return $response;
    }
}

class Crypt
{
    private const APP_VERSION = "8zEwNPUoTQnWd3b0jizzTwoPNjJJz7K1BQA=";
    private const PUBLIC_KEY = "CwgsCjPWz0tKTwwPzApyM/cI9sgzdbG1BQA=";
    private const PRIVATE_KEY = "S/NysUg2CQsL8jYJqyzQznALsqz00LfIdy4uC0gKD/MK83MKzPJ2qgx19A7QDw8KKQ+KDAt1Ngp2DXLX9tYO8AAA";
    private const APP_ID = "047Qz8uKcDZ18XMM8Uj3KDKtSPELCzVPLDFNiwrLL/WrivQsNPA1jirNMjVzykuN9A7N8s6w9PfJLMjOCAlMSQQA";
    private const API_KEY = "SzIIjnDMSszPcDUuNo8sKi5JKbcMNCv2LU3JdwqPck3yDjMMLXQ1T/IIDQtMKzD1c4nKcgnwDy7IqKzMca0KcgcA";
    private const CHAR_SET = "i3L1jcgKzEh2dQoN9g02CgjzzQjTdkv2LMpzC9Q3rtAOt4xIysst9QjIcDX1LE7MrAyz0DbOza1y9NWPdPEoMjAqSC72yPCscskuSw/O96hwSzGtNCl0NQ2zTCwJyDV3cs7L9E2MiPL0TC+xBQA=";

    public static function klik_sign(string $body): string
    {
        $conc = self::dec_react(self::PRIVATE_KEY) . self::dec_react(self::PUBLIC_KEY) . self::dec_react(self::APP_VERSION) . $body;
        $md5 = strtoupper(md5($conc));
        $sha1 = strtoupper(sha1($md5));
        return $sha1;
    }

    public static function x_sign(string $body, string $method = "POST"): string
    {
        $timernow = time();
        $nanoid = self::gen_nanoid();
        $body_md5 = base64_encode(md5($body, true));
        $conc1 = self::dec_react(self::APP_ID) . strtoupper($method) . $timernow . $nanoid . $body_md5;
        $conc2 = base64_encode(hash_hmac("sha256", $conc1, base64_decode(self::dec_react(self::API_KEY)), true));
        return self::dec_react(self::APP_ID) . ":$conc2:$nanoid:$timernow";
    }

    private static function gen_nanoid(): string
    {
        $bytes = random_bytes(32);
        $char_set = self::dec_react(self::CHAR_SET);
        $len = strlen($char_set);
        $ret = "";
        for ($i = 0; $i < 32; $i++) {
            $ret .= $char_set[ord($bytes[$i]) % $len];
        }
        return $ret;
    }

    private static function dec_react(string $str): string
    {
        $REACT_KEY = "2x4x1x0x2x0x0xSxIxGxNxAxTxUxRxEx";
        $REACT_IV = "devKxLxIxKxIxDxM";
        return openssl_decrypt(
            base64_decode(str_rot13(gzinflate(base64_decode($str)))),
            "aes-256-cbc", $REACT_KEY, OPENSSL_RAW_DATA, $REACT_IV
        );
    }
};
function formatTanggal($tanggal) {
    $date = new DateTime($tanggal);
    return $date->format('d M Y'); 
}
function createheaderx($host = null, $idne = null, $token = null, $sign = null)
{
    $headers = array();
    $headers[] = 'Content-Type: application/json';
    $headers[] = 'Applicationkey: indomaret';
    $headers[] = 'User-Agent: okhttp/3.12.1';
    if ($host !== null) {
        $headers[] = 'Host: ' . $host;
    }
    if ($idne !== null && $token !== null) {
        $headers[] = 'Authorization: Bearer ' . $idne . '#' . $token;
    }
    if ($sign !== null) {
        $headers[] = 'X-Signature: ' . $sign;
    }
    return $headers;
}

function nanoidx($length = 21)
{
    $urlAlphabet = 'ModuleSymbhasOwnPr-0123456789ABCDEFGHIJKLNQRTUVWXYZ_cfgijkpqtvxz';
    $result = '';
    $bytes = random_bytes($length);
    for ($i = 0; $i < $length; $i++) {
        $result .= $urlAlphabet[ord($bytes[$i]) & 63];
    }
    return $result;
}

function base64Encodex($str)
{
    return base64_encode($str);
}

function md5Hashx($str)
{
    return md5($str);
}

function hmacSHA256x($data, $key)
{
    return base64_encode(hash_hmac('sha256', $data, base64_decode($key), true));
}

function headersSignaturex($data, $method)
{
    $API_KEY = 'QaTW3xlf1U5ljdlAJSdltzT71fFF+eZ=';
    $APP_ID = 'a1386f30-27ff-4642-8890-da33416c6768';
    $c = strtoupper($method);
    $s = str_pad(strval(time()), 3, '0', STR_PAD_LEFT);
    $_ = nanoidx(32);
    $P = $data;
    $v = base64Encodex(md5Hashx($P));
    $S = $APP_ID . $c . $s . $_ . $v;
    $A = hmacSHA256x($S, $API_KEY);
    return "$APP_ID:$A:$_:$s";
}
function generatesign($e = '{"Email":"0812","Password":"akusopojane", "IsRemember": false}', $b = 'a1386f30-27ff-4642-8890-da33416c6768')
{
    // ################################################
    $t = floor(time());
    $n = function () {
        return array_reduce(crypto_random_valuesx(32), function ($e, $t) {
            return $e . (($t &= 63) < 36 ? base_convert($t, 10, 36) : ($t < 62 ? base_convert($t - 26, 10, 36) : ($t > 62 ? '-' : '_')));
        }, '');
    };
    $n = $n();
    $o = json_encode($e);
    $a = base64_encode(md5($o));
    $r = $b . 'POST' . $t . $n . $a;
    $p = base64_encode(hash_hmac('sha256', strval($r), base64_decode('QaTW3xlf1U5ljdlAJSdltzT71fFF+eZ'), true));
    $result = $b . ':' . $p . ':' . $n . ':' . $t;
    return $result;
}

// ################################################
function crypto_random_valuesx($length)
{
    // ################################################
    $bytes = random_bytes($length);
    return array_values(unpack('C*', $bytes));
}

function detail($gameid,$deviceId, $signat, $token){
    $url = "https://edtsapp.indomaretpoinku.com/game/api/game/$gameid/reward-detail";
    $headers = createHeaders($deviceId, $signat, null, $token, 'edtsapp.indomaretpoinku.com');
    $response = curl($url, null, $headers, "GET");
    $responseArray = json_decode($response, true);
    $detail = $responseArray['data']['couponName'];
    $description = $responseArray['data']['description'];
    return [
            'detail' => $detail,
            'description' => $description,
        ];
}


function menu()
{
    date_default_timezone_set('Asia/Jakarta');
    $directories = array('Master_Akun', 'File_Akun', 'Ada_Kado', 'Ada_Poin','Akun_KLIK');
    foreach ($directories as $dir) {
        if (!file_exists($dir)) {
            mkdir($dir, 0777, true);
        }
    }

    $currentDateTime = date("l, d-m-Y   h:i A"); 
    $maxLength = 48;

    printf("\033[97;1m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
    printf(
        "\033[97;1m┃ \033[96;1m%-13s\033[92;1m[  \033[92;1m %-33s ]\033[92;1m%-4s \033[96;1m%-1s \033[97;1m┃\n",
        "╔══",
        $currentDateTime,
        "",
        "══╗"
    );
    printf("\033[97;1m┃ \033[96;1m%-54s \033[96;1m%-1s \033[97;1m┃\n", "║", "║");
    printf("\033[97;1m┃ \033[97;1m%-19s    M E N U     \033[92;1m%s%-20s\033[97;1m┃ \n", "", "", "");
    printf("\033[97;1m┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫\n");

    $options = [
        "REGIS AKUN POIN",
        "LOGIN AKUN LAMA",
        "INPUT KUPON",
        "GENERATE TOKEN POTONG POIN",
        "PECAH KADO",
        "CEK DAN KLAIM MISI",
        "CEK RIWAYAT",
        "CEK KUPON",
        "BUAT BARCODE KUPON",
        "CEK DAN TUKAR POIN",
        "CEK DAN TUKAR STAMP",
        "CEK JUMLAH KUPON TERSEDIA",
        "BOT SCAN MEMBER",
        "EDIT PROFIL",
    ];

    foreach ($options as $key => $option) {
        $index = $key + 1;
        $formattedOption = str_pad($option, $maxLength); 
        $format = $index < 10 ? "[ %2d ]" : "[ %2d ]";  
        printf("\033[97;1m┃ \033[93;1m$format \033[92;1m%s\033[97;1m┃\n", $index, $formattedOption);
    }

    printf("\033[97;1m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n");
}

function klaimmisi($taskId, $signature, $token) {
    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => "https://edtsapp.indomaretpoinku.com/missionprocessor/apix0107x/mobile/tasks/{$taskId}/claim",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_HTTPHEADER => [
            'authorization: Bearer ' . $token,
            'connection: Keep-Alive',
            'host: edtsapp.indomaretpoinku.com',
            'key: ZWR0czIwMjE6MHBsbW9rbg==',
            'signature: ' . $signature,
            'user-agent: okhttp/5.0.0-alpha.5'
        ],
    ]);

    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);

    return $err ? $err : $response;
}

function cekpinpoin($nomor, $idne, $token, $deviceid) {
  $Signature = $idne . $nomor . 'KlikPoinku' . 'K1k@p01nKu';
  $Signature = strtoupper($Signature);
  $md5Hashx = strtoupper(md5($Signature));
  $sha1Hash = strtoupper(sha1($md5Hashx));

  $postData = json_encode([
      'nomor' => $nomor,
      'customerId' => $idne,
      'signature' => $sha1Hash
  ]);
  $klik_signature = Crypt::klik_sign($postData);
  $x_signature = headersSignaturex($postData,'POST');
  $url = 'https://wallet-payment-pointku.klikindomaret.com/paymentcenter/api/Poinku/CheckPinWallet';
  $headers = [
    'applicationkey: indomaret',
    'authorization: Bearer '.$idne.'#'.$token,
    'cache-control: no-cache, no-store, must-revalidate',
    'connection: Keep-Alive',
    'content-type: application/json',
    'expires: 0',
    'host: wallet-payment-pointku.klikindomaret.com',
    'mobileapp: {"source_name":"apps","os_name":"Android","os_version":"10","device_class":"phone","device_family":"xiaomi","app_version":"2409300","device_id":"'.$deviceid.'"}',
    'pragma: no-cache',
    'user-agent: okhttp/3.12.10',
    'x-forwarded-for: 192.168.1.5',
    'x-signature: ' . $x_signature,
    'klik-signature: ' . $klik_signature,
  
  ];
  $response = curl($url,$postData,$headers,'POST');
  echo $response . n .n ;
  $responseData = json_decode($response,true);
  if (isset($responseData['isPinExist'])) {
      return $responseData['isPinExist'];  
  } else {
      return null;  
  }
}

function buatpinpoin($nomor, $idne, $token, $deviceid, $pin) {
  $Signature = $idne . $nomor . 'KlikPoinku' . 'K1k@p01nKu';
  $Signature = strtoupper($Signature);
  $md5Hashx = strtoupper(md5($Signature));
  $sha1Hash = strtoupper(sha1($md5Hashx));

  $postData = json_encode([
      'nomor' => $nomor,
      'customerId' => $idne,
      'pin' => $pin,
      'signature' => $sha1Hash
  ]);
  
  $klik_signature = Crypt::klik_sign($postData);
  $x_signature = headersSignaturex($postData,'POST');
  
  $url = 'https://wallet-payment-pointku.klikindomaret.com/paymentcenter/api/Poinku/CreatePinPoinku';
  $headers = [
    'applicationkey: indomaret',
    'authorization: Bearer '.$idne.'#'.$token,
    'cache-control: no-cache, no-store, must-revalidate',
    'connection: Keep-Alive',
    'content-type: application/json',
    'expires: 0',
    'host: wallet-payment-pointku.klikindomaret.com',
    'mobileapp: {"source_name":"apps","os_name":"Android","os_version":"10","device_class":"phone","device_family":"xiaomi","app_version":"2409300","device_id":"'.$deviceid.'"}',
    'pragma: no-cache',
    'user-agent: okhttp/3.12.10',
    'x-forwarded-for: 192.168.1.5',
    'x-signature: ' . $x_signature,
    'klik-signature: ' . $klik_signature,
  ];
  
  $response = curl($url,$postData,$headers,'POST');
  echo 'buatpin : ' . $response . n .n ;
  $msg = json_decode($response)->responseMessage;
  return $msg;  
}

function createHeaders($deviceId, $signature = null, $appid = null, $token = null, $host = null) {
    $headers = [
        'accept-encoding: gzip',
        'apps: {"app_version":"3.32.0","device_class":"Phone","device_family":"Xiaomi M2007J20CG","device_id":"' . $deviceId . '","os_name":"Android Q","os_version":"Android 10"}',
        'content-type: application/json; charset=UTF-8',
        'key: ZWR0czIwMjE6MHBsbW9rbg==',
        'user-agent: okhttp/5.0.0-alpha.5'
    ];
    if ($signature !== null) {
        $headers[] = 'signature: ' . $signature;
    }
    if ($appid !== null) {
        $headers[] = 'appid: ' . $appid;
    }
    if ($token !== null) {
        $headers[] = 'authorization: Bearer ' . $token;
    }
    if ($token !== null) {
        $headers[] = 'Host: ' . $host;
    }
    return $headers;
}

function curl($url, $postData = null, $headers = [], $method = null) {
    $curl = curl_init();

    if ($method == 'POST') {
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => $postData,  
            CURLOPT_HTTPHEADER => $headers,   
        ]);
    } elseif ($method == 'GET') {
        if ($postData) {
            $url = $url . '?' . http_build_query($postData);
        }
        curl_setopt_array($curl, [
            CURLOPT_URL => $url, 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_HTTPHEADER => $headers,
        ]);
    }

    $response = curl_exec($curl);
    $err = curl_error($curl);

    curl_close($curl);
    if ($err) {
        return 'cURL Error #:' . $err;
    } else {
        return $response;
    }
}

function regis($deviceId, $nomor) {
    $url = 'https://edtsapp.indomaretpoinku.com/login/apix0107x/open/login-miscall';
    $postData = json_encode([
        'deviceId' => $deviceId,
        'nomor' => $nomor
    ]);
    $signature = SignatureService::signature($nomor, $postData);
    $sign = json_decode($signature);
    $signature = $sign -> signature;
    $appid = $sign -> appid;

    $headers = createHeaders($deviceId, $signature);
    $response = curl($url, $postData, $headers, "POST");

    return $response;
}

function verif($deviceId, $nomor, $otp) {
    $url = 'https://edtsapp.indomaretpoinku.com/login/apix0107x/open/login-verification-miscall';
    $postData = json_encode([
        'deviceId' => $deviceId,
        'otp' => $otp,
        'nomor' => $nomor
    ]);
    $signature = SignatureService::signature($nomor, $postData);
    $sign = json_decode($signature);
    $signature = $sign -> signature;
    $appid = $sign -> appid;

    $headers = createHeaders($deviceId, $signature);
    $response = curl($url, $postData, $headers, "POST");

    return $response;
}

function buatpin($deviceId, $nomor, $pin, $token) {
    $url = 'https://edtsapp.indomaretpoinku.com/login/apix0107x/pin/create-pin';
    $postData = json_encode([
        'pinCode' => $pin
    ]);
    $signature = SignatureService::signature($nomor, $postData);
    $sign = json_decode($signature);
    $signature = $sign -> signature;
    $appid = $sign -> appid;
    $headers = createHeaders($deviceId, $signature, $appid, $token);
    $response = curl($url, $postData, $headers, "POST");

    return $response;
}

function retrieveText($file, $init, $end, $sulfix = '')
{
    $i = 1;
    $output = '';

    $handle = fopen($file, 'r');
    while (false === feof($handle) && $i <= $end) {
        $data = fgets($handle);

        if ($i >= $init) {
            $output .= $data . $sulfix;
        }
        $i++;
    }
    fclose($handle);

    return $output;
}

function save($data, $filePath, $nomor = null) {
    $lines = file_exists($filePath) ? file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    
    $found = false; 
    foreach ($lines as &$line) {
        if (strpos($line, $nomor) !== false) {
            $line = $data; 
            $found = true;
            break;
        }
    }   
    if (!$found) {
        $lines[] = $data;  
    }
    $lines = array_filter($lines, function($line) {
        return trim($line) !== '';  
    });

    file_put_contents($filePath, implode("\n", $lines) . "\n");
}


function pilihFile($folderPath) {
    if (!is_dir($folderPath)) {
        echo "Folder '$folderPath' tidak ditemukan.\n";
        return null;
    }

    $files = array_diff(scandir($folderPath), ['.', '..']);
    if (empty($files)) {
        echo "Folder '$folderPath' kosong.\n";
        return null;
    }

    echo kuning . "Daftar file $folderPath:\n";
    $files = array_values($files); 
    $no = 0;
    foreach ($files as $index => $file) {
        $index = $no + 1;
        $format = $index < 1000 ? "[ %1d ]" : "[ %5d ]";  
        printf("\033[93;1m$format \033[92;1m%s\n", $index, strtoupper($file));
        $no++;
    }

    echo kuning . "Pilih file : ";
    $pilihan = trim(fgets(STDIN));

    if (!is_numeric($pilihan) || $pilihan < 1 || $pilihan > count($files)) {
        echo "Pilihan tidak valid.\n";
        return null;
    }

    $fileTerpilih = $files[$pilihan - 1];

    return $folderPath . DIRECTORY_SEPARATOR . $fileTerpilih;
}

function processBatch($line, $apiBaseUrl, $outputDir)
{
    $multiHandle = curl_multi_init();
    $curlHandles = [];
    $outputFiles = [];
    $failedItems = [];

        $filename = $outputDir . $line . '.png';
        $outputFiles[$line] = $filename;

        echo "Menyiapkan data: $line\r";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $apiBaseUrl . urlencode($line));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);

        $curlHandles[$line] = $ch;
        curl_multi_add_handle($multiHandle, $ch);
    echo "Memulai pengunduhan barcode...\n";
    do {
        $status = curl_multi_exec($multiHandle, $running);
        curl_multi_select($multiHandle);
    } while ($running > 0);

    foreach ($curlHandles as $line => $ch) {
        $barcodeImage = curl_multi_getcontent($ch);

        if (curl_errno($ch) || !$barcodeImage) {
            echo "Gagal mengambil barcode untuk: $line\n";
            $failedItems[] = $line; 
        } else {
            file_put_contents($outputFiles[$line], $barcodeImage);
            echo "Barcode untuk '$line' berhasil disimpan di {$outputFiles[$line]}.\n";

            addTextToImage($outputFiles[$line], $outputDir);
        }

        curl_multi_remove_handle($multiHandle, $ch);
        curl_close($ch);
    }

    curl_multi_close($multiHandle);

    return $failedItems;
}

function addTextToImage($imagePath, $text)
{
    $image = imagecreatefrompng($imagePath);
    if (!$image) {
        echo "Gagal memuat gambar: $imagePath\n";
        return;
    }

    $origWidth = imagesx($image);
    $origHeight = imagesy($image);

    $frameSize = 40;

    $newWidth = $origWidth + (2 * $frameSize);
    $newHeight = $origHeight + (2 * $frameSize);
    $newImage = imagecreatetruecolor($newWidth, $newHeight);

    $white = imagecolorallocate($newImage, 255, 255, 255);
    imagefill($newImage, 0, 0, $white);

    imagecopy($newImage, $image, $frameSize, $frameSize, 0, 0, $origWidth, $origHeight);

    $textColor = imagecolorallocate($newImage, 0, 0, 0);

    $font = __DIR__ . '/arial.ttf';
    $fontSize = 12;
    $x = 10;
    $y = $newHeight - 10;

    if (file_exists($font)) {
        imagettftext($newImage, $fontSize, 0, $x, $y, $textColor, $font, $text);
    } else {
        imagestring($newImage, 5, $x +60, $y - 187, $text, $textColor);
    }

    imagepng($newImage, $imagePath);

    imagedestroy($image);
    imagedestroy($newImage);
}

function handlenomorInput($chatId, $nomor) {
  global $bot, $validnomors, $client;
  
  $poinkuNumber = $validnomors[$nomor] ?? null;
  if (!$poinkuNumber) {
      $randomnomor = $validnomors[array_rand($validnomors)]; 
      $poinkuNumber = $randomnomor ; 
  }

  $url = "https://edtsapp.indomaretpoinku.com/customer/apix0107x/mobile/customer-promotions?param={$poinkuNumber}";
  $headers = array(
      'authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI2OFMwalUzbGdFaU1zbzFWRDgzRHhhdEk3blkxLU9WR1dQSVI4d0F2MVgwIn0.eyJleHAiOjE3Mzg2NTA1MTcsImlhdCI6MTczMzQ2NjUxNywianRpIjoiMTM2Mjk2MTQtYzBiNi00YzAxLWExNTQtMGUyNGU5NzgzNDNkIiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay5pbmRvbWFyZXRwb2lua3UuY29tL2tleWNsb2FrL2F1dGgvcmVhbG1zL2lkbS1hcHAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiYjNlNmMwY2EtMjFiOS00ZjEyLWE2ZDktYWJiMzJkY2Y1YjVjIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiaWRtLWJvIiwic2Vzc2lvbl9zdGF0ZSI6Ijc1NjllMTdmLTkzNzUtNDc4Ni05MzVmLTNhMmJlNjhmZDI2ZSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLWlkbS1hcHAiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIG1vYmlsZSIsInNpZCI6Ijc1NjllMTdmLTkzNzUtNDc4Ni05MzVmLTNhMmJlNjhmZDI2ZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiaWQiOjMyMjM5MzAxLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiIwODU3NTQ2MDM1MTI6OnBvaW4wODU3NTQ2MDM1MTIifQ.e1gv1unaD71sk8hljWJOs-7B4t2QHBGXyGzUjerMq3fMeTqGJYRX0SWYyiseeSe-THth4oczsTrL7tpoRX_jRclzX8Y-rjfJmVHSn6hNfHnJpzJwbZnto6aBQwenwi9ZQz8DdeoQ4skLaTrfDtfJH6rl0-PakEKwWavYIl1deVZkzzbzjDf4rJKMl7DCtnnTGTIbgT4zujceliZ33c-FcxWZaP6nf2u0RtfwdWPG2vuzRLd_g0Lr9-o3Gngpfzwzwm1qLhGY5Pj8kK6PJZuYrdV3cq5F6HEA3Y0EXWjA-Xuad7dtFvvQ5xIoLofadb2qYlFppiiqLlQ6YxLwSdnAfg',
      'key: ZWR0czIwMjE6MHBsbW9rbg==',
      'signature: MsL2cUpum+Q7SUc9a+7VlJndcpr4STDjIgl4U8cUcOsUDjg5g73mxxt5yms7jtX6i3/z9DtLcAVZmdggWlVKb/6I9cdP7DEo5hiJiYqhII4nsYB/h3yLr7hfPxymBNatRUJSvmcgvsKA28QboIS6FlEcOKByiAP7ysGlxZ36xQXlPv54dfyy5m75BcaeXKVPLVtiInRH+uY38uuGka0g+i6xvzGnKH7nVmdX9MgBjtmjtvl9/F4AmxH8Fsc5wdVLP+Z/OIaXOe+aGV3Zk/tTZo1hnLsUpdASeX9cVLlb5pI6QCNIMMYtDXmfCop4GiCjv3fkrXh7+y+C6k1Q3XWQgQ==',
      'accept-encoding: gzip',
      'user-agent: okhttp/5.0.0-alpha.5',
  );
  
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
  $response1 = curl_exec($ch);
  $responseArray = json_decode($response1, true);
  $message = $responseArray['message'];
  $dataqr = $responseArray['data']['encodedData'];
  
  if ($dataqr) {
    echo hijau . "Barcode Member akun ke $nomor => " . kuning . $poinkuNumber . '  Berhasil dibuat' . n;

    $qrSize = "30x30"; 
    $qrUrl = "https://api.qrserver.com/v1/create-qr-code/?data=" . urlencode($dataqr) . "&chs={$qrSize}";
    $qrImage = file_get_contents($qrUrl);
    file_put_contents("qr_temp.png", $qrImage); 
    
    $backgroundWidth = 550;
    $backgroundHeight = 350;

    $background = imagecreatefromjpeg("https://idm-pub-img-prod.s3.ap-southeast-3.amazonaws.com/configuration/promo-banner/2f7453dc-3e46-49cb-ba3c-083f2d2b6438.jpg");

    if (!$background) {
        die("Gagal memuat gambar latar belakang.");
    }

    list($bgWidth, $bgHeight) = getimagesize("https://idm-pub-img-prod.s3.ap-southeast-3.amazonaws.com/configuration/promo-banner/2f7453dc-3e46-49cb-ba3c-083f2d2b6438.jpg");
    $backgroundResized = imagecreatetruecolor($backgroundWidth, $backgroundHeight);
    imagecopyresampled($backgroundResized, $background, 0, 0, 0, 0, $backgroundWidth, $backgroundHeight, $bgWidth, $bgHeight);
    imagedestroy($background);
    $background = $backgroundResized;

    $qrCode = imagecreatefrompng("qr_temp.png");
    list($qrWidth, $qrHeight) = getimagesize("qr_temp.png");

    $borderSize = 10; 
    $qrWithBorder = imagecreatetruecolor($qrWidth + $borderSize * 2, $qrHeight + $borderSize * 2);
    $white = imagecolorallocate($qrWithBorder, 255, 255, 255); 
    imagefill($qrWithBorder, 0, 0, $white);
    imagecopy($qrWithBorder, $qrCode, $borderSize, $borderSize, 0, 0, $qrWidth, $qrHeight);

    $qrX = ($backgroundWidth - ($qrWidth + $borderSize * 2)) / 2;
    $qrY = ($backgroundHeight - ($qrHeight + $borderSize * 2)) / 2;

    imagecopy($background, $qrWithBorder, $qrX, $qrY, 0, 0, $qrWidth + $borderSize * 2, $qrHeight + $borderSize * 2);

    $finalImage = "qr_with_background.png";
    imagepng($background, $finalImage);

    unlink("qr_temp.png"); 

    $bot->sendPhoto($chatId, curl_file_create($finalImage), "ONE IX MEMBER. Segera Lakukan Scan, Waktu Hanya 1 Menit. Jika expired silahkan ketik ulang nomor urut");
    unlink($finalImage); 

    imagedestroy($background); 
    imagedestroy($qrCode); 
    imagedestroy($qrWithBorder); 
} else {
    $bot->sendMessage($chatId, "Sedang terjadi eror! Silahkan ulangi input nomor urut");
}

}


function showjam() {
  $jam = date('H'); 
  $user = "UNCLE71";
  if ($jam >= 4 && $jam < 11) {
      return "\033[93;1mSelamat pagi !  \033[1m" . "\033[92;1m$user\033[0m" . "";
  } elseif ($jam >= 11 && $jam < 17) {
      return "\033[93;1mSelamat siang ! \033[1m" . "\033[92;1m$user\033[0m" . "";
  } else {
      return "\033[93;1mSelamat malam ! \033[1m" . "\033[92;1m$user\033[0m" . "";
  }
}

awal:
printf("\033[97;1m┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
printf("\033[97;1m┃ \033[96;1m%-21s\033[92;1m%-24s\033[96;1m%-12s \033[96;1m%-1s \033[97;1m┃\n", "╔══", showjam(), "","══╗");
printf("\033[97;1m┃ \033[96;1m%-54s \033[96;1m%-1s \033[97;1m┃\n", "║","║");
printf("\033[97;1m┃ \033[92;1m      ██    █     █  ████        ███    █     █       \033[97;1m ┃\n");
printf("\033[97;1m┃ \033[92;1m    █    █  ██    █  █            █      █   █        \033[97;1m ┃\n");
printf("\033[97;1m┃ \033[92;1m    █    █  █  █  █  ███          █        █          \033[97;1m ┃\n");
printf("\033[97;1m┃ \033[92;1m    █    █  █    ██  █            █      █   █        \033[97;1m ┃\n");
printf("\033[97;1m┃ \033[92;1m      ██    █     █  ████        ███    █     █       \033[97;1m ┃\n");
printf("\033[97;1m┃ \033[96;1m%-54s \033[96;1m%-1s \033[97;1m┃\n", "║","║");
printf("\033[97;1m┃ \033[96;1m%-26s \033[93;1m%-15s \033[92;1m%-13s \033[96;1m%-1s \033[97;1m┃\n", "╚══","SC POIN", "","══╝");
printf("\033[97;1m┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n");

menu();
echo  "\033[93;1mPILIH : \033[96;1m";
$choice = trim(fgets(STDIN));
echo "\n";
$signat = 'MsL2cUpum+Q7SUc9a+7VlJndcpr4STDjIgl4U8cUcOsUDjg5g73mxxt5yms7jtX6i3/z9DtLcAVZmdggWlVKb/6I9cdP7DEo5hiJiYqhII4nsYB/h3yLr7hfPxymBNatRUJSvmcgvsKA28QboIS6FlEcOKByiAP7ysGlxZ36xQXlPv54dfyy5m75BcaeXKVPLVtiInRH+uY38uuGka0g+i6xvzGnKH7nVmdX9MgBjtmjtvl9/F4AmxH8Fsc5wdVLP+Z/OIaXOe+aGV3Zk/tTZo1hnLsUpdASeX9cVLlb5pI6QCNIMMYtDXmfCop4GiCjv3fkrXh7+y+C6k1Q3XWQgQ==';

switch ($choice) {
    case '1':

        echo sp . hijau . "PIN    : " . biru ;
        $pin = trim(fgets(STDIN));
        if ($pin == ''){
            break;
        }
        regis :
        echo sp . hijau .  "NO HP  : " . biru ;
        $nomor = trim(fgets(STDIN));
        $device = "KLIK$nomor";
        ulangregis :
        $res = regis($device, $nomor);
        $data = json_decode($res, true);
        $msg = $data['message'];
        if ($msg == "Success") {
            echo sp . hijau .  "OTP    : " . biru ;
            $otp = trim(fgets(STDIN));
            if ($otp == ''){
                goto ulangregis;
            }
            $res = verif($device, $nomor, $otp);
            $data = json_decode($res, true);
            $token = $data['data']['access_token'];
            $res = buatpin($device, $nomor, $pin, $token);
            $data = json_decode($res, true);
            $msg = $data['message'];
            echo sp . hijau . 'STATUS  : ' . $msg . n . n ;
            save($nomor . ' | ' . $device . ' | ' . $pin . "\n", "Master_Akun/poinregis.txt",$nomor);
            save($nomor . ' | ' . $device . ' | ' . $token . "\n", "File_Akun/mytoken.txt",$nomor);

            echo sp . kuning . 'Data di simpan pada ' . biru . 'Master_Akun/poinregis.txt' . n . n;
            echo putih . garis . n . n;

        } else {
            echo $res . n . n;
        }
        goto regis;
        break;
    

    case '2';
    echo spp . putih . "[ " . kuning . "1." . putih . " ]" . hijau . " 👉 SET PIN POIN AKUN KLIK" . n ;
    echo spp . putih . "[ " . kuning . "2." . putih . " ]" . hijau . " 👉 LOGIN DARI AKUN POIN" . n . n;

    echo kuning . spp . "PILIH : " . biru;
    $menu = trim(fgets(STDIN));

    if ($menu == "1") {
        echo n . kuning . 'Password Login KLIK : ' . biru ;
        $pass = trim(fgets(STDIN));
        echo kuning . 'SET PIN POIN        : ' . biru ;
        $pin = trim(fgets(STDIN));

        $file = pilihFile("Akun_KLIK");
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        $no = 0;
        foreach ($lines as $line_num => $line) {
            $akunxx1= explode('|', trim($line));
            $nomore = trim($akunxx1[0]);
            $index = $no + 1;
            $format = $index < 1000 ? "[ %2d ]" : "[ %5d ]";  
            printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        $no++;
        }
        echo "\n";
        echo "\033[93;1mStart baris ke    : \033[96;1m";
        $start = trim(fgets(STDIN));
        echo "\033[93;1mSampai baris ke   : \033[96;1m";
        $endd = trim(fgets(STDIN));
        $filex = retrieveText($file, $start, $endd);
        $list = explode("\n", str_replace("\r", "", $filex));
        $no = 0;

        foreach ($list as $task) {
            if (strpos($task, '|') !== false) {
                $akunxx = explode('|', trim($task));
                $nomor = trim($akunxx[0]);
                $device_id = trim($akunxx[1]);
                if (stripos($device_id, 'KLIK') !== false || stripos($device_id, 'poin') !== false || stripos($device_id, 'POIN') !== false) {
                    $device_id = trim($akunxx[1]);
                } else {
                    $device_id = 'KLIK' . $nomor;
                }
            } elseif (strpos($task, ':') !== false) {
                $akunxx = explode(':', trim($task));
                $nomor = trim($akunxx[0]);
                $device_id = trim($akunxx[2]);

                if (stripos($device_id, 'KLIK') !== false || stripos($device_id, 'poin') !== false || stripos($device_id, 'POIN') !== false) {
                    $device_id = trim($akunxx[2]);
                } 
            } else {
                $nomor = trim($task);
                $device_id = 'KLIK' . $nomor;

            }
            $datanee = '{"Email":"' . $nomor . '","Password":"' . $pass . '", "IsRemember": false}';
            $str = strlen($datanee);
            $sign = generatesign(json_decode($datanee));
            $url = 'https://prd-api.klikindomaret.com/Account/Customer/Login?isMobile=true&method=APPS&mfp_id=1&deviceID=' . $device_id . '&deviceName=WebKit&device_token=null&districtID=2483&type=null&Location=-7.669069901417355,%20112.11599304308807';
            $headers = createheaderx('prd-api.klikindomaret.com', null, null, $sign);
            $response = curl($url, $datanee, $headers, "POST");
            $responseData = json_decode($response, true);
            $respi = $responseData['data'];
            $pesan = $respi['Message'];
            if (isset($respi['ResponseObject']['Token'])) {
                $respid = $respi['ResponseID'];
                $idne = $respi['ResponseObject']['ID'];
                $token = $respi['ResponseObject']['Token'];
                $pesan = $respi['Message'];
                $nama = $respi['ResponseObject']['FName'];
                echo orange . $no . ". " . putih . $nomor . kuning . " LOGIN $pesan " . putih . ' => ';

                save($nomor . ' | ' . $device_id . ' | ' . $respid . ' | ' . $idne . ' | ' . $token . "\n", "Akun_KLIK/Token_Klik.txt",$nomor);
                $pinnya = cekpinpoin($nomor, $idne, $token, $device_id);
                save($nomor . ' | ' . $device_id . "\n", "Master_Akun/akunklik.txt");                       
                if ($pinnya == false) {
                 $pinpoin = buatpinpoin($nomor, $idne, $token, $device_id, $pin);
                  save($nomor . ' | ' . $device_id . ' | ' . $pin ."\n", "Master_Akun/akunklik.txt",$nomor);
                  echo hijau . $pin . " $pinpoin " . n ;
                } else {
                    echo hijau . " $pinnya " . n ;
                }

            } else {
            	echo orange . $no . ". " . putih . $nomor . merah . " LOGIN $pesan " . n ;
            }
            
            $no++;
        }
        
        break;

    } else {
        echo sp . hijau . "PIN    : " . biru ;
        $pin = trim(fgets(STDIN));

        $file = pilihFile("Master_Akun");
        $fileName = basename($file);
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        $no = 0;
        foreach ($lines as $line_num => $line) {
            if (strpos($line, '|') !== false) {
                $akunxx = explode('|', trim($line));
                $nomore = trim($akunxx[0]);
            } elseif (strpos($line, ':') !== false) {
                $akunxx = explode(':', trim($line));
                $nomore = trim($akunxx[0]);
            } 
            $index = $no + 1;
            $format = $index < 1000 ? "[ %2d ]" : "[ %5d ]";  
            printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        $no++;
        }
    
        echo "\n";
        echo "\033[93;1mStart baris ke    : \033[96;1m";
        $start = trim(fgets(STDIN));
        echo "\033[93;1mSampai baris ke   : \033[96;1m";
        $endd = trim(fgets(STDIN));
        $filex = retrieveText($file, $start, $endd);
    
        echo"\033[97;1m┏━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n";
        echo "\033[97;1m┃\033[93;1m" . str_pad("No", 5, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad(" Nomor Handphone ", 15, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("KETRANGAN", 34, " ", STR_PAD_BOTH) . "\033[97;1m┃\n";
        echo"\033[97;1m┣━━━━━╋━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫\n";
        
        $list = explode("\n", str_replace("\r", "", $filex));
        $no = $start;
       
        foreach ($list as $kode) {                                                              
        if(empty($kode)) {
                continue;
            }

            if (strpos($kode, '|') !== false) {
                $akunxx = explode('|', trim($kode));
                $nomor = trim($akunxx[0]);
                $deviceId = trim($akunxx[1]);
            } elseif (strpos($kode, ':') !== false) {
                $akunxx = explode(':', trim($kode));
                $nomor = trim($akunxx[0]);
                $deviceId = trim($akunxx[2]);
            } 
            $data = array(
              "deviceId" => $deviceId,
              "phoneNumber" => $nomor,
              "pinCode" => $pin
          );
            $body = json_encode($data);
            $signature = SignatureService::signature($nomor, $body);
            $sign = json_decode($signature);
            $signature = $sign -> signature;
            $appid = $sign -> appid;          
          
            $url = "https://edtsapp.indomaretpoinku.com/login/apix0107x/open/pin/validate-pin";
            $headers = createHeaders($deviceId, $signature);
            $response = curl($url, $body, $headers, "POST");
            $responseArray = json_decode($response, true);
            $message = $responseArray['message'];
            $no = str_pad($no . ".", 5, " ", STR_PAD_BOTH);
            $nomor = str_pad($nomor, 16, " ", STR_PAD_BOTH);
            $msg = str_pad($message, 33, " ", STR_PAD_BOTH);
            if ($message == "Success"){
                $accessToken = $responseArray['data']['access_token'];
            echo "\033[97;1m┃\033[93;1m$no\033[97;1m┃\033[97;1m $nomor\033[97;1m┃\033[92;1m $msg\033[97;1m┃\n";
            save($nomor . ' | ' . $deviceId . ' | ' . $accessToken ."\n", "File_Akun/mytoken $fileName",$nomor);

            } else {
                save($nomor . ' | ' . $deviceId . ' | ' . $pin ."\n", "Master_Akun/Gagallogin.txt",$nomor);
                echo "\033[97;1m┃\033[93;1m$no\033[97;1m┃\033[97;1m $nomor\033[97;1m┃\033[91;1m $msg\033[97;1m┃\n";
            }
            $no++;               
        }
        echo"\033[97;1m┗━━━━━┻━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n";

        break;
    }

    case '3':
        echo merah . 'Menu ini sementara belum tersedia' . n ;
        break;


    case '4':
        echo sp . kuning . 'LAKUKAN CEK POIN TERLEBIH DAHULU UNTUK SORTIR AKUN' . n . n ; 
        echo sp . hijau . "PIN    : " . biru ;
        $pin = trim(fgets(STDIN));
        if ($pin == ''){
            break;
        }
        echo n . sp .  kuning . 'Tampilkan QR (y/n) ? : ' . biru ;
        $kodeqr = trim(fgets(STDIN));
        $file = pilihFile("Ada_Poin");
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        $no = 0;
        foreach ($lines as $line_num => $line) {
            $akunxx1= explode('|', trim($line));
            $nomore = trim($akunxx1[0]);
            $index = $no + 1;
            $format = $index < 1000 ? "[ %2d ]" : "[ %5d ]";  
            printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        $no++;
        }

        echo "\n";
        echo "\033[93;1mStart baris ke    : \033[96;1m";
        $start = trim(fgets(STDIN));
        echo "\033[93;1mSampai baris ke   : \033[96;1m";
        $endd = trim(fgets(STDIN));
        $filex = retrieveText($file, $start, $endd);
        $list = explode("\n", str_replace("\r", "", $filex));
        $no = $start;
      
        foreach ($list as $kode) {                                                              
        if(empty($kode)) {
                continue;
            }
            $akunxx = explode('|', trim($kode));
            $nomor = trim($akunxx[0]);
            $deviceId = trim($akunxx[1]);
            $token = trim($akunxx[2]);
            $data = array(
              "deviceId" => $deviceId,
              "nomor" => $nomor,
              "pinCode" => $pin
          );
            $body = json_encode($data);
            $signature = SignatureService::signature($nomor, $body);
            $sign = json_decode($signature);
            $signature = $sign -> signature;
            $appid = $sign -> appid; 
            $url = "https://edtsapp.indomaretpoinku.com/wallet/apix0107x/mobile/balance";
            $headers = createHeaders($deviceId, $signat, $appid, $token);
            $response = curl($url, null, $headers, "GET");
            $json = json_decode($response, true);
            $status = $json['message'];
            $message = $json['message'];
            $poin = $json['data']['balance'];
            echo "\033[93;1mNo Hp   : \033[96;1m[ $nomor ]\n";
            echo "\033[93;1mPoinmu  : \033[97;1mRp " . number_format($poin, 0, ',', '.')."\n";

            $data = json_encode(array("pinCode" => "708090")); 
            $signature = SignatureService::signature($nomor, $data);
            $sign = json_decode($signature);
            $signature = $sign -> signature;
            $appid = $sign -> appid; 
            $url = 'https://edtsapp.indomaretpoinku.com/wallet/apix0107x/mobile/activation-wallet';
            $headers = createHeaders($deviceId, $signature, $appid, $token);
            $response = curl($url, $data, $headers, "POST");
            $json = json_decode($response, true);
            $msg = $json['message'];
            if ($msg == "Success") {
                echo "\033[93;1mStatus  : \033[92;1m$msg\n";
                barcode :
                $url = 'https://edtsapp.indomaretpoinku.com/customer/apix0107x/mobile/customer-promotions?param='.$nomor;
                $headers = createHeaders($deviceId, $signat, $appid, $token);
                $response = curl($url, null, $headers, "GET");
                $json = json_decode($response, true);
                $message = $json['message'];
                $dataqr = $json['data']['encodedData'];
                echo "\033[93;1mKode QR : \n";
                // echo $dataqr . n . n ;
                $barcode_url = "https://api.qrserver.com/v1/create-qr-code/?data=". urlencode($dataqr)."&chs=250x250";
                $os = PHP_OS_FAMILY; 
                $sapi = PHP_SAPI; 
                if ($os === 'Windows') {
                    shell_exec("start $barcode_url");
                } elseif ($os === 'Darwin') {
                    shell_exec("open '$barcode_url'");
                } elseif ($os === 'Linux') {
                    shell_exec("xdg-open '$barcode_url'");
                } else {
                    echo $barcode_url . "\n";
                }
                if ($kodeqr == 'y') {
                    $command = 'echo "' . $dataqr . '" | qrencode -t ANSIUTF8';
                    $output = shell_exec($command);
                    echo $output;
                }
                echo sp . hijau . "ENTER untuk lanjut : " . biru ;
                $pin = trim(fgets(STDIN));
                echo n . putih . garis . n . n ;
                                
        }
    }
    break;

    case '5':
    pecah:
    echo spp . putih . "[ " . kuning . "1." . putih . " ]" . hijau . " 👉 CEK KADO SAJA" . n;
    echo spp . putih . "[ " . kuning . "2." . putih . " ]" . hijau . " 👉 LANGSUNG KLAIM KADO" . n;
    echo spp . putih . "[ " . kuning . "3." . putih . " ]" . hijau . " 👉 TAMPILKAN HASIL CEK KADO" . n . n;
    echo kuning . spp . "PILIH : " . biru;
    $menu = trim(fgets(STDIN));
    if($menu == '3'){
        $folderPath = 'Ada_Kado';
            $no = 0;

            if (is_dir($folderPath)) {
                $files = scandir($folderPath);
                foreach ($files as $file) {
                    if ($file != "." && $file != "..") {
                        $filePath = $folderPath . '/' . $file;
                        if (is_file($filePath)) {
                            $lineCount = count(file($filePath));
                            $unwantedWords = array(".txt", "!");
                            $file = str_replace($unwantedWords, "", $file);
                            $file = preg_replace("/\([^)]+\)/", "", $file);
                            $no = str_pad($no . ".", 3, " ");
                            $lineCount = str_pad($lineCount, 5, " ");
                            $file = substr($file, 0, 80);
                            $file = str_pad($file, 80, " ");
                            echo " $no \033[93;1m▶ \033[92;1m$file:   \033[97;1m$lineCount \033[96;1mkupon\n";
                            $no++;
                        }
                        
                    }
                }
            } else {
                echo "Folder '$folderPath' tidak ditemukan.\n";
            }
            echo n . n ;
            break;
    }

    if($menu == '1'){

    $file = pilihFile("File_Akun");
    } else {
        echo spp . putih . "[ " . kuning . "1." . putih . " ]" . hijau . " 👉 AKUN SUDAH CEK KADO" . n;
        echo spp . putih . "[ " . kuning . "2." . putih . " ]" . hijau . " 👉 SEMUA AKUN" . n . n;
        echo kuning . spp . "PILIH : " . biru;
        $akunnya = trim(fgets(STDIN));
        if($akunnya == '1') {
            $file = pilihFile("File_Akun");
        } else {
            $file = pilihFile("Ada_Kado");
        }

    }
    $lines = file($file, FILE_IGNORE_NEW_LINES);
    $no = 0;
    foreach ($lines as $line_num => $line) {
        $akunxx1= explode('|', trim($line));
        $nomore = trim($akunxx1[0]);
        $index = $no + 1;
        $format = $index < 1000 ? "[ %2d ]" : "[ %5d ]";  
        printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
    $no++;
    }

    echo "\n";
    echo "\033[93;1mStart baris ke    : \033[96;1m";
    $start = trim(fgets(STDIN));
    echo "\033[93;1mSampai baris ke   : \033[96;1m";
    $endd = trim(fgets(STDIN));
    $filex = retrieveText($file, $start, $endd);
    $list = explode("\n", str_replace("\r", "", $filex));
    $no = $start;

    echo"\033[97;1m┏━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━┓\n";
    echo "\033[97;1m┃\033[93;1m" . str_pad("No", 5, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Nomor Handphone", 15, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Nama Kado", 30, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Status", 9, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Expired", 14, " ", STR_PAD_BOTH) . "\033[97;1m┃\n";
    echo"\033[97;1m┣━━━━━╋━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━╋━━━━━━━━━━━━━━┫\n";

    foreach ($list as $kode) {                                                              
    if(empty($kode)) {
            continue;
        }
        $akunxx = explode('|', trim($kode));
        $nomor = trim($akunxx[0]);
        $deviceId = trim($akunxx[1]);
        $token = trim($akunxx[2]);
        $no = str_pad($no . ".", 5, " ", STR_PAD_BOTH);
        echo "\033[97;1m┃\033[93;1m$no\033[97;1m┃";
        $no++;
        $nomor = str_pad($nomor, 15, " ", STR_PAD_BOTH);
        echo "\033[97;1m$nomor\033[97;1m┃";
        
        $url = "https://edtsapp.indomaretpoinku.com/game/apix0107x/customer-game/get-unused";
        $headers = array(
            "Authorization: bearer $token",
            "Sec-Fetch-Site: same-site",
            "Accept-Language: id-ID,id;q=0.9",
            "Sec-Fetch-Mode: cors",
            "Accept: application/json, text/plain, */*",
            "Origin: https://indomaretpoinku.com",
            "Connection: keep-alive",
            "Referer: https://indomaretpoinku.com/",
            "Sec-Fetch-Dest: empty"
          );
        $response = curl($url, null, $headers, "GET");
        $listkado = json_decode($response, true);
        $content = $listkado['data']['content'];
        if ($content == null) {
                $gameName = "Tidak ada Kado";
                $kupon = str_pad(mb_substr($gameName, 0, 30, 'UTF-8'), 30, " ", STR_PAD_BOTH);
                echo "\033[91;1m$kupon\033[97;1m┃";
                $space = "-";
                $space1 = str_pad($space, 9, " ",STR_PAD_BOTH);
                echo "\033[91;1m$space1\033[97;1m┃";
                $space2 = str_pad($space, 14, " ",STR_PAD_BOTH);
                echo "\033[91;1m$space2\033[97;1m┃\n";
            
        } else {
            foreach ($content as $index => $item) {
            $id = $item['id'];
            $nomor = $item['phoneNumber'];
            $idgame = $item['game']['id'];
            $gameName = $item['game']['title'];
            $validDate = $item['validDate'];
            $expiredDate = date('d-m-Y', strtotime($item['expiredDate']));
            $datane = detail($idgame,$deviceId, $signat, $token);
            $description = $datane['description'];
            $safeDescription = preg_replace('/[\/\\\\:*?"<>|]/', '-', $description);
            $safeDescription = preg_replace('/\s+/', ' ', $safeDescription);
            $safeDescription = trim($safeDescription);
            $safeDescription = substr($safeDescription, 0, 255);          
            $safeDescription = str_replace('Selamat, kamu terpilih dapetin promo spesial ', '', $safeDescription);
            $safeDescription = str_replace('Yuk pakai sekarang!', '', $safeDescription);
            $safeDescription = str_replace('i-Kupon ini dapat ditukarkan di', 'Di', $safeDescription);
            $safeDescription = str_replace('Indomaret', 'IDM', $safeDescription);
            $safeDescription = str_replace('toko', 'Toko', $safeDescription);
            $safeDescription = trim($safeDescription);
            
            if ($gameName == "Promo Cashback Up to 30K") {
                $kupon = str_pad(mb_substr($gameName, 0, 30, 'UTF-8'), 30, " ", STR_PAD_BOTH);
                echo "\033[92;1m$kupon\033[97;1m┃";
            } else {
                $kupon = str_pad(mb_substr($gameName, 0, 30, 'UTF-8'), 30, " ", STR_PAD_BOTH);
                echo "\033[96;1m$kupon\033[97;1m┃";
            }
            if($menu == '1'){            

            $tanggal = str_pad($expiredDate, 14, " ", STR_PAD_BOTH);
            echo "\033[91;1m$space1\033[97;1m┃\033[93;1m$tanggal\033[97;1m┃\n";
        
            if ($content > 0) {
                $combo = "\033[97;1m┃     ┃               ";
                echo "\033[93;1m$combo\033[97;1m┃";
            }
        }
            $namaFolder = 'Ada_Kado' ;
            if (!is_dir($namaFolder)) {
                mkdir($namaFolder);
            }
            $fileName = $namaFolder . '/' . $safeDescription." ( ".$expiredDate." )".'.txt';
            save($nomor . ' | ' . $deviceId . ' | ' . $token . "\n", $fileName, $nomor);
            if($menu == '2'){            
            $headers = array(
                'Content-Type: application/json',
                'Accept: application/json, text/plain, */*',
                'Origin: https://indomaretpoinku.com',
                'Authorization: Bearer ' . $token,
                'User-Agent: okhttp/3.12.1'
            );
            
            $datac = array(
                'customerGameId' => $id
            );
            $url = 'https://edtsapp.indomaretpoinku.com/game/apix0107x/customer-game/play-game';
            $body = json_encode($data);
            $response = curl($url, $body, $headers, "POST");
            $response = curl_exec($curl);
            $pecah = json_decode($response, true);
            $pecahx = $pecah['data']['content'];
            $pesan = $pecah['message'];
            $kupon = $pecah['data']['content'][0]['name'];
            if ($pesan == "Success") {
                $kupon = str_pad(mb_substr($pesan, 0, 37, 'UTF-8'), 9, " ", STR_PAD_BOTH);
                    echo "\033[92;1m$kupon\033[97;1m┃";
            } else {
                $kupon = str_pad(mb_substr($pesan, 0, 37, 'UTF-8'), 9, " ", STR_PAD_BOTH);
                    echo "\033[92;1m$kupon\033[97;1m┃";
            }
            $tanggal = str_pad($expiredDate, 14, " ", STR_PAD_BOTH);
                echo "\033[93;1m$tanggal\033[97;1m┃\n";
            if ($content > 0) {
                    $combo = "\033[97;1m┃     ┃               ";
                    echo "\033[93;1m$combo\033[97;1m┃";
            }
        }
        }
            $gameName = "";
            $kupon = str_pad(mb_substr($gameName, 0, 30, 'UTF-8'), 30, " ", STR_PAD_BOTH);
            echo "\033[91;1m$kupon\033[97;1m┃";
            $space = "";
            $space1 = str_pad($space, 9, " ",STR_PAD_BOTH);
            echo "\033[91;1m$space1\033[97;1m┃";
            $space2 = str_pad($space, 14, " ",STR_PAD_BOTH);
            echo "\033[91;1m$space2\033[97;1m┃\n";

    }
}
    $no++;
    echo"\033[97;1m┗━━━━━┻━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━┻━━━━━━━━━━━━━━┛\n";
    echo "\n\n";
    
    
    
    echo "\033[93;1mMau Pecah Kado Lagi ? ( y/n ) : \033[96;1m";
      
      $yn = trim(fgets(STDIN));
      if ($yn == 'y') {
      goto pecah;
      }
      break;

    case '6':
        echo spp . putih . "[ " . kuning . "1." . putih . " ]" . hijau . " 👉 CEK MISI" . n ;
        echo spp . putih . "[ " . kuning . "2." . putih . " ]" . hijau . " 👉 KLAIM MISI" . n . n ;
        echo kuning . spp . "PILIH : " . biru;
        $menu = trim(fgets(STDIN));
        if($menu == '1') {
            $folder = 'Ada_Poin';

            if (is_dir($folder)) {
                foreach (glob("$folder/*") as $file) {
                    if (is_file($file)) {
                        $fileName = basename($file);
                        if (strpos($fileName, 'MISI') !== false && pathinfo($file, PATHINFO_EXTENSION) === 'txt') {
                            unlink($file);
                        }
                    }
                }
            }

            $file = pilihFile("File_Akun");
            $lines = file($file, FILE_IGNORE_NEW_LINES);
            $no = 0;
            foreach ($lines as $line_num => $line) {
                $akunxx1= explode('|', trim($line));
                $nomore = trim($akunxx1[0]);
                $index = $no + 1;
                $format = $index < 100 ? "[ %2d ]" : "[ %2d ]";  
                printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
            $no++;
            }
        
            echo "\n";
            echo "\033[93;1mStart baris ke    : \033[96;1m";
            $start = trim(fgets(STDIN));
            echo "\033[93;1mSampai baris ke   : \033[96;1m";
            $endd = trim(fgets(STDIN));
            $filex = retrieveText($file, $start, $endd);
            $list = explode("\n", str_replace("\r", "", $filex));
            $no = $start;
            foreach ($list as $kode) {
                if(empty($kode)) {
                    continue;
                }
    
                $akunxx = explode('|', trim($kode));
                $nomor = trim($akunxx[0]);
                $deviceId = trim($akunxx[1]);
                $token = trim($akunxx[2]);
                $url = 'https://edtsapp.indomaretpoinku.com/missionview/apix0107x/mobile/v2/missions/6';
                $headers = createHeaders($deviceId, $signat, null, $token, 'edtsapp.indomaretpoinku.com');
                $response = curl($url, null, $headers, "GET");
                $data = json_decode($response, true);

                $customerAmount = $data['data']['tasks'][0]['customerAmount'];
                if (isset($data['data']['tasks'])) {
                    foreach ($data['data']['tasks'] as $task) {
                        $description = $task['description'];
                        $claimed = $task['claimed'];
                        $amount = $task['amount'];
                        $customerAmount = $task['customerAmount'];
                
                        if ($claimed == false && $customerAmount >= $amount) {
                            $dataToSave = "$nomor | $deviceId | $token ";
                            $namaFolder = "Ada_Poin";
                            $fileNamex = $namaFolder . '/' . "Misi " . $description . '.txt';
                            if (!is_dir($namaFolder)) {
                                mkdir($namaFolder, 0777, true);
                            }
                            
                            $fileContent = file_exists($fileNamex) ? file($fileNamex, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
                            
                            $phoneExists = false;
                            foreach ($fileContent as $line) {
                                $lineParts = explode('|', $line);
                                if (trim($lineParts[0]) === $nomor) {
                                    $phoneExists = true;
                                    break;
                                }
                            }
                            
                            if (!$phoneExists) {
                                $fileContent[] = $dataToSave;
                            }
                            file_put_contents($fileNamex, implode("\n", $fileContent) . "\n");        
                
                        }
                    }
                }
                echo "$no. \033[97;1m$nomor  =>  \033[93;1m$customerAmount %\n";
                if ($customerAmount < 500) {
                    $dataToSave = "$nomor | $deviceId | $token | $customerAmount";
                    $namaFolder = "Ada_Poin";
                    $namakupon = "Belum Complete";
                    $fileName = $namaFolder . '/' . $namakupon . '.txt';
                    
                    if (!is_dir($namaFolder)) {
                        mkdir($namaFolder, 0777, true);
                    }
                    
                    $fileContent = file_exists($fileName) ? file($fileName, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];                   
                    $phoneExists = false;
                    foreach ($fileContent as $index => $line) {
                        $lineParts = explode('|', $line);
                        if (trim($lineParts[0]) === $nomor) {
                            $phoneExists = true;
                            if ((int)trim($lineParts[3]) !== $customerAmount) {
                                $fileContent[$index] = $dataToSave;
                            }
                            break;
                        }
                    }
                    
                    if (!$phoneExists) {
                        $fileContent[] = $dataToSave;
                    }
                        usort($fileContent, function($a, $b) {
                        $aParts = explode('|', $a);
                        $bParts = explode('|', $b);
                        return (int)trim($bParts[3]) - (int)trim($aParts[3]);
                    });
                    file_put_contents($fileName, implode("\n", $fileContent) . "\n");
                    
                }
                
                $no++;
                
                  }
                  if (file_exists($fileName)) {
                    $lines = file($fileName, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                
                        $kategori1 = [];
                        $kategori2 = [];
                        $kategori3 = [];
                        $kategori4 = [];
                
                        foreach ($lines as $line) {
                            $parts = explode('|', $line);
                            $customerAmount = (int)trim($parts[3]);
                
                            if ($customerAmount >= 50 && $customerAmount <= 149) {
                                $kategori1[] = $line;
                            } elseif ($customerAmount >= 150 && $customerAmount <= 299) {
                                $kategori2[] = $line;
                            } elseif ($customerAmount >= 300 && $customerAmount <= 499) {
                                $kategori3[] = $line;
                            } 
                        }
                        $filePath = "Ada_Poin/Misi Belanja Rp 500.000.txt";

                        if (file_exists($filePath)) {
                            $fileContents = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                            $jmlKategori4 = count($fileContents);
                        }
                            
                 $jmlKategori1 = count($kategori1);
                        $jmlKategori2 = count($kategori2);
                        $jmlKategori3 = count($kategori3);
                        echo "\n\n";
                        echo kuning . sp . "JUMLAH AKUN YANG BELUM KLAIM MISI" . n . n ;
                        echo "\033[97;1m ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
                        echo "\033[92;1mMisi kategori  50        : \033[97;1m$jmlKategori1 \033[93;1mAkun\n";
                        echo "\033[92;1mMisi kategori  150       : \033[97;1m$jmlKategori2 \033[93;1mAkun\n";
                        echo "\033[92;1mMisi kategori  300       : \033[97;1m$jmlKategori3 \033[93;1mAkun\n";
                        echo "\033[92;1mMisi kategori  500       : \033[97;1m$jmlKategori4 \033[93;1mAkun\n";
                        echo "\033[97;1m ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
                
                } else {
                    echo "File tidak ditemukan.\n";
                } 
                break;
        } else {
            $file = pilihFile("Ada_Poin");
            $lines = file($file, FILE_IGNORE_NEW_LINES);
            $no = 0;
            foreach ($lines as $line_num => $line) {
                $akunxx1= explode('|', trim($line));
                $nomore = trim($akunxx1[0]);
                $index = $no + 1;
                $format = $index < 100 ? "[ %2d ]" : "[ %2d ]";  
                printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
            $no++;
            }
        
            echo "\n";
            echo "\033[93;1mStart baris ke    : \033[96;1m";
            $start = trim(fgets(STDIN));
            echo "\033[93;1mSampai baris ke   : \033[96;1m";
            $endd = trim(fgets(STDIN));
            $filex = retrieveText($file, $start, $endd);
            $list = explode("\n", str_replace("\r", "", $filex));
            $no = $start;
            foreach ($list as $kode) {
                if(empty($kode)) {
                    continue;
                }
                $akunxx = explode('|', trim($kode));
                $nomor = trim($akunxx[0]);
                $deviceId = trim($akunxx[1]);
                $token = trim($akunxx[2]);
                $tasks = [
                    ['id' => 30, 'signature' => 'v2sNZWnivvITGtzY6sRGJqXt0HoPpa1P2Q7vhhO90fZLZa56GupTvJV/2bIzrZy1XdD38juEju/rOj4ePVhkw+chtsmZPLDKxSHPDnfKaWSCVvMWWFP29XpH6ZZSOgcGrQjxQmP+D5Fe3uknvu58HyQO2v5Ps6YZlMTaj+MfUBDR8dvi30HjHzfy0s3jHVV+PLe3tDVf/3VDAPW7lHMTyBYVy/F7PftB30Etswr4Cnhb6SmN8EywVmwDKhqYgddDPfy9H33kiBGlQOvP/km5m6K+Emqo/hQTvQ5XEcV3xeR74jz49CE+wy+Hepk6TlSFbtGfYhjZTrFmJldgnmvhSQ=='],
                    ['id' => 31, 'signature' => 'seEICHo3Zf9kD0cPDpSEgh1X+952LTDgTb536IJ7e75WWQ3QWbIPTWhFPpRt4+VSZT7HjJfFZi/BInwetrAMgda5Jc4bRzyygc5rbP+HrrgwoJznE6DLZ8ZNypBceYA3LhfHOL2OU5l3UYGD4+gk9o0I4WXHx0KuaUirRyutoM8J0PFPABHaY1RmDasGCkkh8R75PLzypuEyWgGUkEuwZzzPkvKX1R9RfmjKTfPfJQgGw55UzIAyhJY7xOkm5kuM/mCvALx0MH+89skbgIkAVdpqykIWBg1XTj2D7SoI5fPk5xIU7Tg4ysbR2bqtO8Yn4J7mxNtTfeQsv5gY+5IvhA=='],
                    ['id' => 32, 'signature' => 'EhZpHKGygoUeskQPGBS2wGHZdd7+Xw0d/5ks3GgPkeneSGt7rvsSXyRGqm0JxGUxAHA+1s03c+zDg9f2D9l8J2iT5O7FlbD9JSxAfQxXD1nFwj4M/1EccpPC2KqxlYSZ3+WLNKB171jFWsgM/iMsRZyE3MaDIUnXEBnmBrDVvyjGTLUidO8mGgWA9PPNfTHy5jukLgBidYJAWI+Jz8ZFjRnvmixNnqmkOKHywWxLYXo2v5/ZYfwe6eej/dfl1KtGpBuOn242NBTRUVXYPw4dOV2FA/z37FzdswgetsPKLCdpVJvWXcAq3EzGVwQQ91MXp9BFFOBvVQvZY+tgtcMJgA=='],
                    ['id' => 33, 'signature' => 'lmVebztk8fNok3hlsqFX8BWC3VcNG82g/6OsWvu6ndjxlWaFR59/QnVBvDZjrVEJXXR5OqDo24uCNtk6hq2HOr0xb9TT+TzrjqQ/mLxBXPcAU0/k0ncsJ77M0buLSsTp0QlBQB+dPC9bp0MTIXVD++M3DkLAeq0rB/Os6oongTJYmC71kmOW/Qk+qwPx8SRtUHwM3AUff6AkEyjghvv9aOwLFX5NDp4q2/yhzeR24dcVRoOX2CilqimC3IpGRTIGutK6hkecwuyqAWvcrTcbFEp2Za5+Fb7SWkb3k7xbbLvvms1x0fC5a7hiuk6Ots6ewHd1UfKmKfCnsohnEK/wCA==']
                ];
            
                foreach ($tasks as $task) {
                    echo "\033[97;1m $no. ";
                    echo "\033[97;1m $nomor => ";

                    $data = klaimmisi($task['id'], $task['signature'], $token);
                    $data = json_decode($data);
                    $msg = $data -> message;
                    if ($msg == "Success"){
                        echo "\033[92;1m " . $msg . "\n";
                    } else {
                        echo "\033[91;1m " . $msg . "\n";
                    }
                }
            $no++;

            }    

        }

        break;


    case '7':
        $file = pilihFile("File_Akun");
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        $no = 0;
        foreach ($lines as $line_num => $line) {
            $akunxx1= explode('|', trim($line));
            $nomore = trim($akunxx1[0]);
            $index = $no + 1;
            $format = $index < 100 ? "[ %2d ]" : "[ %2d ]";  
            printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        $no++;
        }
    
        echo "\n";
        echo "\033[93;1mStart baris ke    : \033[96;1m";
        $start = trim(fgets(STDIN));
        echo "\033[93;1mSampai baris ke   : \033[96;1m";
        $endd = trim(fgets(STDIN));
        $filex = retrieveText($file, $start, $endd);
        $list = explode("\n", str_replace("\r", "", $filex));
        $no = $start;
        
        echo"\033[97;1m┏━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━┓\n";
        echo "\033[97;1m┃\033[93;1m" . str_pad("No", 5, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Nomor Handphone", 15, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Nama TRX", 30, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Poin/Stamp", 11, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Tanggal TRX", 12, " ", STR_PAD_BOTH) . "\033[97;1m┃\n";
        echo"\033[97;1m┣━━━━━╋━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━━━━━┫\n";

        foreach ($list as $kode) {
            if(empty($kode)) {
                continue;
            }

            $akunxx = explode('|', trim($kode));
            $nomor = trim($akunxx[0]);
            $deviceId = trim($akunxx[1]);
            $token = trim($akunxx[2]);

        $no = str_pad($no . ".", 5, " ", STR_PAD_BOTH);
        echo "\033[97;1m┃\033[97;1m$no\033[97;1m┃";
        $no++;
        $nomor = str_pad($nomor, 15, " ", STR_PAD_BOTH);
        echo "\033[97;1m$nomor\033[97;1m┃";
        $url = 'https://edtsapp.indomaretpoinku.com/payment/apix0107x/mobile/getTransaction?page=0&size=1000&type=h2';
        $headers = createHeaders($deviceId, $signat, null, $token, 'edtsapp.indomaretpoinku.com');
        $response = curl($url, null, $headers, "GET");
        $responsex = json_decode($response, true);
        $content = $responsex['data']['content'];
        
        $currentMonth = date('m'); 
        $maxLength = '30';
        foreach ($content as $item) {
            
            $transactionMonth = date('m', strtotime($item['transactionDate'])); 
            if ($transactionMonth == $currentMonth) { 
                if ($item['transactionType'] == "earn stamp") {     	
                    $kupon = str_pad("Stamp  ".$item['stampName'], $maxLength, " ", STR_PAD_BOTH);
                    $kupon = mb_substr($kupon, 0, 30, 'UTF-8');
                    echo "\033[92;1m$kupon\033[97;1m┃";       
                    $jumlah = str_pad($item['amount'], 11, " ", STR_PAD_BOTH);
                    echo "\033[92;1m$jumlah\033[97;1m┃";       
                   } elseif ($item['transactionType'] == "earn point") {
                    $kupon = "Stamp Poin";
                    $kupon = str_pad($kupon, $maxLength, " ", STR_PAD_BOTH);
                    $kupon = mb_substr($kupon, 0, 30, 'UTF-8');
                    echo "\033[93;1m$kupon\033[97;1m┃";
                    $jumlah = str_pad($item['amount'], 11, " ", STR_PAD_BOTH);
                    echo "\033[97;1m$jumlah\033[97;1m┃";
                    } else {
                    $kupon = str_pad(strval($item['transactionName']), 42, " ", STR_PAD_BOTH);
                    $kupon = mb_substr($kupon, 0, 42, 'UTF-8');
                    echo "\033[96;1m$kupon\033[97;1m┃";
                    }

                    $tanggal = date('d-m-Y', strtotime($item['transactionDate']));
                    $tanggal = str_pad($tanggal, 12, " ", STR_PAD_BOTH);
                    echo "\033[93;1m$tanggal\033[97;1m┃\n";
                    if ($content > 1) {
                    $combo = "\033[97;1m┃     ┃               ";
                    echo "\033[93;1m$combo\033[97;1m┃";
                    } 
        
                 }
            
        }
                $space = "";
                $space0 = str_pad($space, 30, " ");
                $space1 = str_pad($space, 11, " ");
                $space2 = str_pad($space, 12, " ");
                echo "\033[93;1m$space0\033[97;1m┃\033[93;1m$space1\033[97;1m┃\033[93;1m$space2\033[97;1m┃\n";
                
            }
            
        echo"\033[97;1m┗━━━━━┻━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━┻━━━━━━━━━━━━┛\n";
        break;
        

    case '8':
        echo spp . putih . "[ " . kuning . "1." . putih . " ]" . hijau . " 👉 SEMUA AKUN" . n ;
        echo spp . putih . "[ " . kuning . "2." . putih . " ]" . hijau . " 👉 AKUN MISI COMPLETE" . n . n ;
        echo kuning . spp . "PILIH : " . biru;
        $menu = trim(fgets(STDIN));
        if($menu == '1') {
            $file = pilihFile("File_Akun");
        } else {
            $file = pilihFile("Ada_Poin");
        }
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        $no = 0;
        foreach ($lines as $line_num => $line) {
            $akunxx1= explode('|', trim($line));
            $nomore = trim($akunxx1[0]);
            $index = $no + 1;
            $format = $index < 100 ? "[ %2d ]" : "[ %2d ]";  
            printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        $no++;
        }
    
        echo "\n";
        echo "\033[93;1mStart baris ke    : \033[96;1m";
        $start = trim(fgets(STDIN));
        echo "\033[93;1mSampai baris ke   : \033[96;1m";
        $endd = trim(fgets(STDIN));
        $filex = retrieveText($file, $start, $endd);
        $list = explode("\n", str_replace("\r", "", $filex));
        $no = $start;
        echo"\033[97;1m┏━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━┓\n";
        echo "\033[97;1m┃\033[93;1m" . str_pad("No", 5, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Nomor Handphone", 15, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Nama Kupon", 30, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Kode", 11, " ", STR_PAD_BOTH) . "   \033[97;1m┃\033[93;1m" . str_pad("Expired", 12, " ", STR_PAD_BOTH) . "\033[97;1m┃\033[93;1m" . str_pad("Penggunaan", 13, " ", STR_PAD_BOTH) . "\033[97;1m┃\n";
        echo"\033[97;1m┣━━━━━╋━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━━━┫\n";
               
        foreach ($list as $kode) {
            if (empty($kode)) {
                continue;
            }
            $akunxx = explode('|', trim($kode));
            $nomor = trim($akunxx[0]);
            $deviceId = trim($akunxx[1]);
            $token = trim($akunxx[2]);

            $signature = SignatureService::signature($nomor, $deviceId);
            $sign = json_decode($signature);
            $appid = $sign -> appid;
            $no = str_pad($no . ".", 5, " ", STR_PAD_BOTH);
            echo "\033[97;1m┃\033[97;1m$no\033[97;1m┃";
            $nomor = str_pad($nomor, 15, " ", STR_PAD_BOTH);
            echo "\033[97;1m$nomor\033[97;1m┃";
            $no++;
            $url = "https://edtsapp.indomaretpoinku.com/coupon/apix0107x/mobile/coupons?page=0&sort=isValidStartDate%2Cdesc&sort=expiredDate%2Casc&size=1000";
            $headers = createHeaders($deviceId, $signat, $appid, $token, 'edtsapp.indomaretpoinku.com');
            $response = curl($url, null, $headers, "GET");
            $data = json_decode($response, true);
            $content = $data['data']['content'];            
            $pesan = $data['message'];
            if ( $pesan == "Success" && $content !== null) {
            foreach ($content as $item) {
            $namakupon = str_replace('/', ' atau', $item['couponName']);
            $kodekupon = $item['couponCode'];
            $expired = formatTanggal($item['expiredDate']);
            $valid_store = $item['validStore'];
            $imageUrl = $item['imageUrl'];
            $kupon = str_pad(mb_substr($namakupon, 0, 30, 'UTF-8'), 30, " ", STR_PAD_BOTH);
            echo "\033[93;1m$kupon\033[97;1m┃";
            
            $kodekupon = str_pad($kodekupon, 14, " ",STR_PAD_BOTH);
            echo "\033[92;1m$kodekupon\033[97;1m┃";
            $expired = str_pad($expired, 12, " ",STR_PAD_BOTH);
            echo "\033[93;1m$expired\033[97;1m┃";
            
            if ($valid_store == ["OFFLINE_STORE","KLIK"] ) {
                    echo " TOKO & KLIK ";
                } else {
                foreach ($valid_store as $store) {
                    $store = str_pad($store, 13, " ",STR_PAD_BOTH);
                    echo $store ;
                }
            }
            echo "\033[97;1m┃\n";
            $description = $item['description'];
            $parts = explode("\n", $description);
            $firstPart = $parts[0];
            $description = str_replace('/', ' atau ', $firstPart);
            $unwantedWords = array("Selamat, kamu terpilih dapetin promo spesial", "i-Kupon ini dapat ditukarkan di toko Indomaret / Klik Indomaret","Yuk pakai sekarang!", "(tidak berlaku kelipatan).","NOTE" ,"\n\n");
        
            $description = str_replace($unwantedWords, "", $description);
            $expired = preg_replace('/[<>:"\/\\\|\?\*]/', '', $expired);
            $description = preg_replace('/[<>:"\/\\\|\?\*]/', '', $description);
            $description = mb_substr($description, 0, 140, 'UTF-8');
            preg_match('/\b(\d+\s?g)\b/', $description, $matches);   
            $folderPath = 'Kupon'; 

            if (!is_dir($folderPath)) {    
                mkdir($folderPath, 0777, true);
            }
            
            $couponCode = $item['couponCode'];
            $filePath = $folderPath . '/' . $expired . " " . $description . '.txt';
            
            if (!file_exists($filePath)) {
                touch($filePath);
            }
            
            $fileContents = file_get_contents($filePath);
            if (strpos($fileContents, $couponCode) === false) {
                file_put_contents($filePath, $couponCode . "\n", FILE_APPEND);
            }
         if ($content > 0) {
                $combo = "\033[97;1m┃     ┃               ";
                echo "\033[93;1m$combo\033[97;1m┃";
        }
        }
                $gameName = "";
                $kupon = str_pad(mb_substr($gameName, 0, 30, 'UTF-8'), 30, " ", STR_PAD_BOTH);
                echo "\033[91;1m$kupon\033[97;1m┃";
                $space = "";
                $space1 = str_pad($space, 14, " ",STR_PAD_BOTH);
                echo "\033[91;1m$space1\033[97;1m┃";
                $space2 = str_pad($space, 12, " ",STR_PAD_BOTH);
                echo "\033[91;1m$space2\033[97;1m┃";
                echo "\033[91;1m$space2\033[97;1m ┃\n";
        
        }
    }
        echo"\033[97;1m┗━━━━━┻━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━┻━━━━━━━━━━━━┻━━━━━━━━━━━━━┛\n\n";
        break;

    case '9':
        $folder = 'Kupon';

        if (!is_dir($folder)) {
            echo "\033[91;1mFolder \033[96;1m$folder \033[91;1mtidak ditemukan.\n";
        }
        
        $files = array_diff(scandir($folder), array('..', '.'));
        
        if (!empty($files)) {
            echo "\033[93;1mDaftar file dalam folder $folder :\033[92;1m\n\n";
            $files = array_values($files);
        
            foreach ($files as $index => $file) {
                $fileContent = file_get_contents($folder . '/' . $file);
                if (is_file($folder . '/' . $file)) {
                    $lines = explode("\n", $fileContent);
                    $nonEmptyLines = array_filter($lines, 'strlen'); 
                    $jumlahDataBaris = count($nonEmptyLines);
                    $file = preg_replace('/\\.[^.\\s]{3,4}$/', '', $file);
                    $file = substr($file, 0, 45);
                    $file = str_pad($file, 46);
        
                    echo "    \033[93;1m" . str_pad($index + 1, 4) . "▶\033[92;1m  " . $file . " : \033[96;1m ( $jumlahDataBaris ) Kupon \n";
                } else {
                    echo "    \033[93;1m" . str_pad($index + 1, 4) . "▶  \033[96;1m Folder\n";
                }
            }
        
        
        
            echo "\033[93;1m\nPilih (1-" . count($files) . ")\033[97;1m: ";
            $selectedFileNumber = trim(fgets(STDIN));
        
            if ($selectedFileNumber >= 1 && $selectedFileNumber <= count($files)) {
                $selectedFile = $files[$selectedFileNumber - 1];
                $file = $folder . '/' . $selectedFile;
                $fileContent = file_get_contents($file);
        
                $lines = explode("\n", $fileContent); 
                echo "\033[93;1m\nIsi file $selectedFile:\n";
                $i = 1;
        
                foreach ($lines as $line) {
                    $n = str_pad($i.".", 4);
                    echo "   \033[94;1m".$n."\033[92;1m". $line . "\n";
                    $i++;
                }
                echo "\033[93;1m\nMasukkan baris awal  : \033[96;1m";
                $startLine = trim(fgets(STDIN));
        
                echo "\033[93;1mMasukkan baris akhir : \033[96;1m";
                $endLine = trim(fgets(STDIN));
                echo "\n";
                $ndata = $startLine;
                if ($startLine >= 1 && $endLine >= $startLine && $endLine <= count($lines)) {
                    for ($i = $startLine; $i <= $endLine; $i++) {
                        $lineIndex = $i - 1;
                        if (isset($lines[$lineIndex])) {
                            $data = trim($lines[$lineIndex]);
        
                            if (!empty($data)) {
                                $barcode_service_url = "https://barcodeapi.org/api/128/".$data;
                                $image_data = file_get_contents($barcode_service_url);
                                $image = imagecreatefromstring($image_data);
        
                                $pathInfo = pathinfo($selectedFile);
                                $filename = isset($pathInfo['extension']) && strtolower($pathInfo['extension']) === 'txt' ? $pathInfo['filename'] : $pathInfo['filename'];
                                $filename = rtrim($filename);                               
                                $folder_name = "Barcode Kupon/" . preg_replace("/[^A-Za-z0-9]/", ' ', $filename) . "/";                               
                                if (!is_dir($folder_name)) {
                                    mkdir($folder_name, 0777, true); 
                                }
                                
                                $barcodeFilename = "$folder_name/$data.png";
                                imagepng($image, $barcodeFilename);
                                imagedestroy($image);
                                echo "\033[93;1m$ndata. \033[92;1mBarcode \033[96;1m$data\n";
                                $ndata++;
                            }
                        }
                        
                    }
        
                    echo "\n\n\033[92;1mSukses Menyimpan Barcode Kupon\n";
                } else {
                    echo "\033[91;1mNomor baris tidak valid.\n";
                }
            } else {
                echo "Folder kosong.";
            }
        }
        break;


    case '10';

        echo spp . putih . "[ " . kuning . "1." . putih . " ]" . hijau . " 👉 CEK POIN CASH DAN STAMP POIN" . n ;
        echo spp . putih . "[ " . kuning . "2." . putih . " ]" . hijau . " 👉 TUKAR STAMP POIN" . n . n ;
        echo kuning . spp . "PILIH : " . biru;
        $menu = trim(fgets(STDIN));
        $file = pilihFile("File_Akun");
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        $no = 0;
        foreach ($lines as $line_num => $line) {
            $akunxx1= explode('|', trim($line));
            $nomore = trim($akunxx1[0]);
            $index = $no + 1;
            $format = $index < 100 ? "[ %2d ]" : "[ %2d ]";  
            printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        $no++;
        }

        echo "\n";
        echo "\033[93;1mStart baris ke    : \033[96;1m";
        $start = trim(fgets(STDIN));
        echo "\033[93;1mSampai baris ke   : \033[96;1m";
        $endd = trim(fgets(STDIN));
        $filex = retrieveText($file, $start, $endd);
        $list = explode("\n", str_replace("\r", "", $filex));
        $no = $start;
        if ($menu == '1') {
            $folder = 'Ada_Poin';

            if (is_dir($folder)) {
                foreach (glob("$folder/*") as $file) {
                    if (is_file($file)) {
                        $fileName = basename($file);
                        if (strpos($fileName, 'Poin') !== false && pathinfo($file, PATHINFO_EXTENSION) === 'txt') {
                            unlink($file);
                        }
                    }
                }
            }
        $columnHeaders = str_pad("No.", 6, " ", STR_PAD_BOTH) . " ┃ " .
        str_pad("Nomer Hp", 14, " ", STR_PAD_BOTH) . " ┃ " .
        str_pad("Stamp", 18, " ", STR_PAD_BOTH) . " ┃ " .
        str_pad("Poinku", 18, " ", STR_PAD_BOTH). " ┃ " . 
        str_pad("Tier", 8, " ", STR_PAD_BOTH);
        
        echo "\033[93;1m┏━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓\n";
        echo "\033[93;1m┃ \033[92;1m$columnHeaders \033[93;1m┃ \n";
        echo "\033[93;1m┣━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━┫\n";
        $totalPoin = 0; 
        $totalPoine = 0; 
        foreach ($list as $kode) {
            if (empty($kode)) {
                continue;
            }
            $akunxx = explode('|', trim($kode));
            $nomor = trim($akunxx[0]);
            $deviceId = trim($akunxx[1]);
            $token = trim($akunxx[2]);

            $signature = SignatureService::signature($nomor, $deviceId);
            $sign = json_decode($signature);
            $appid = $sign -> appid;
            $url = "https://edtsapp.indomaretpoinku.com/loyalty/apix0107x/mobile/v2/active/points/me";
            $headers = createHeaders($deviceId, $signat, $appid, $token, 'edtsapp.indomaretpoinku.com');
            $response = curl($url, null, $headers, "GET");
            $responseArray = json_decode($response, true);
            $status = $responseArray['message'];
            $message = $responseArray['message'];
            $poin = $responseArray['data']['balance'];
            $totalPoin += $poin;
            $dataRows = array();

            $dataRows[] = array(
                str_pad($nomor, 14, " ", STR_PAD_RIGHT),
                str_pad("Rp " . number_format($poin, 0, ',', '.'), 17, " ", STR_PAD_LEFT),
            );
     
            foreach ($dataRows as $index => $row) {             
                $data = implode(" ┃ ", $row);
                if ($no % 2 == 0) {
                    echo "\033[93;1m┃ \033[97;1m" . str_pad($no . ".", 6, " ", STR_PAD_RIGHT) . " ┃ " . $data . "  \033[93;1m┃";             
                } else {
                    echo "\033[93;1m┃ \033[97;1m" . str_pad($no . ".", 6, " ", STR_PAD_RIGHT) . " ┃ \033[93;1m" . $data . "  \033[93;1m┃";         
                } 
            $no++;
            }
            $url = 'https://edtsapp.indomaretpoinku.com/wallet/apix0107x/mobile/balance';
            $headers = createHeaders($deviceId, $signat, $appid, $token, 'edtsapp.indomaretpoinku.com');
            $response = curl($url, null, $headers, "GET");
            $responseArray = json_decode($response, true);
            $pesan = $responseArray['message'];
            if ($pesan == "Forbidden" || $pesan == "400 BAD_REQUEST" ) {
                $gameName = "Appid salah";
                        $gameName = "Appid salah";
                        $kupon = str_pad(mb_substr($gameName, 0, 30, 'UTF-8'), 20, " ", STR_PAD_BOTH);
                        echo "\033[91;1m$kupon\033[93;1m┃";
                    
                } else {
                    
                $folderName = "Ada_Poin";
                $poin = $responseArray['data']['balance'];
                $totalPoine += $poin;
                $poine = str_pad("Rp " . number_format($poin, 0, ',', '.'), 19, " ", STR_PAD_LEFT);
                echo "\033[92;1m".$poine."\033[93;1m ┃";
                if (!file_exists($folderName)) {
                mkdir($folderName, 0777, true);
                }
                if ($responseArray['data']['balance'] > 1000) { 
                    $filePath = $folderName . '/Poin Diatas 1000.txt';
                    save($nomor . ' | ' . $deviceId . ' | ' . $token . ' | ' . $poin . "\n", $filePath, $nomor);
                    if (file_exists($filePath)) {
                        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                        usort($lines, function($a, $b) {
                            $poinA = (int)explode(' | ', $a)[3]; 
                            $poinB = (int)explode(' | ', $b)[3]; 
                            return $poinB <=> $poinA; 
                        });
                        file_put_contents($filePath, implode("\n", $lines) . "\n");
                    }
                }
                }
            $url = "https://edtsapp.indomaretpoinku.com/tier/apix0107x/mobile/customer-tier-full";
            $headers = createHeaders($deviceId, $signat, $appid, $token, 'edtsapp.indomaretpoinku.com');
            $response = curl($url, null, $headers, "GET");
            $data = json_decode($response,true);
            $tier = $data['data']['tier']['tierName'];
            $tiere = str_pad($tier, 9, " ", STR_PAD_BOTH);
            echo "\033[92;1m".$tiere."\033[93;1m ┃\n";
            } 

            $totalPoin = str_pad("Rp " . number_format($totalPoin, 0, ',', '.'), 19, " ", STR_PAD_LEFT);
            $totalPoine = str_pad("Rp " . number_format($totalPoine, 0, ',', '.'), 19, " ", STR_PAD_LEFT);
            echo "\033[93;1m┣━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━┫\n";
            echo kuning . '┃' . biru . '      ' . kuning . '  ┃   Total' . kuning . '        ┃' .  biru . $totalPoin . kuning . ' ┃' . biru . $totalPoine . kuning . ' ┃     ' . '     ┃' . n ;
            echo "\033[93;1m┗━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━┛\n\n";
    break;
        } else {
            // $columnHeaders = str_pad("No.", 4, " ", STR_PAD_BOTH) . " ┃ " .
            // str_pad("Deskripsi", 54, " ", STR_PAD_BOTH) . " ┃ " .
            // str_pad("Jumlah Poin", 18, " ", STR_PAD_BOTH). " ┃ " . 
            // str_pad("Sisa kuota", 18, " ", STR_PAD_BOTH);
            
            // echo "\033[93;1m┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓\n";
            // echo "\033[93;1m┃ \033[92;1m$columnHeaders \033[93;1m┃ \n";
            // echo "\033[93;1m┣━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━┫\n";
            // $firstLine = $lines[0];
            // $i = 0;
            //     $akunxx = explode('|', trim($firstLine));
            //     $nomor = trim($akunxx[0]);
            //     $deviceId = trim($akunxx[1]);
            //     $token = trim($akunxx[2]);
            //     $signature = SignatureService::signature($nomor, $deviceId);
            //     $sign = json_decode($signature);
            //     $appid = $sign -> appid;
            //     $url = "https://edtsapp.indomaretpoinku.com/loyalty/apix0107x/mobile/points/me/coupons?categoryExchangeId=0&page=0&sort=amount%2Casc&sort=name%2Casc&size=1000";
            //     $headers = createHeaders($deviceId, $signat, $appid, $token, 'edtsapp.indomaretpoinku.com');
            //     $response = curl($url, null, $headers, "GET");
            //     $json = json_decode($response, true);
            //     $content = $json['data']['content'];
            //     $names = [];
            //     $couponIds = [];
            //     $pointExchangeIds = [];
            //     $i = 1; 
                
            //     foreach ($content as $item) {
            //         $pointExchangeId = $item['pointExchangeId'];
            //         $amount = $item['amount'];
            //         $amount = str_pad($amount, 18, " ", STR_PAD_BOTH);
            //         $couponId = $item['couponId'];
            //         $quota = $item['quota'];
            //         $usedQuota = $item['usedQuota'];
            //         $sisakuota = $quota - $usedQuota;
                
            //         $description = $item['description'];
            //         $name = $item['name'];
            //         $namex = str_pad(mb_substr($name, 0, 55, 'UTF-8'), 55, " ", STR_PAD_RIGHT);
                
            //         if ($sisakuota != '0') {
            //             $iFormatted = str_pad($i, 4, " ", STR_PAD_BOTH);  
            //             $sisakuota = str_pad($sisakuota, 18, " ", STR_PAD_BOTH);               
            //             echo kuning . '┃ ' . biru . $iFormatted . kuning . ' ┃ ' . hijau . $namex . kuning . '┃ ' . biru . $amount . kuning . ' ┃ ' . biru . $sisakuota . kuning . ' ┃' . n;
                
            //             $names[$i] = $name;
            //             $couponIds[$i] = $couponId;
            //             $pointExchangeIds[$i] = $pointExchangeId;              
            //             $i++; 
            //         }
            //     }
            //     echo "\033[93;1m┗━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┛\n\n";

            //     pilihkupone:
            //     echo kuning . "Pilih : " . biru;
            //     $selectedNumber = trim(fgets(STDIN)); 
                
            //     if (isset($names[$selectedNumber])) {
            //         $selectedName = $names[$selectedNumber];
            //         $selectedCouponId = $couponIds[$selectedNumber];
            //         $selectedPointExchangeId = $pointExchangeIds[$selectedNumber];
            //         foreach ($list as $kode) {
            //             if (empty($kode)) {
            //                 continue;
            //             }
            //             $akunxx = explode('|', trim($kode));
            //             $nomor = trim($akunxx[0]);
            //             $deviceId = trim($akunxx[1]);
            //             $token = trim($akunxx[2]);
            
            //             $data = array(
            //                 "couponId" => $selectedCouponId,
            //                 "pointExchangeId" => $selectedPointExchangeId,
            //                 "qty" => 1.0
            //             );
            //               $body = json_encode($data);
            //               $signature = SignatureService::signature($nomor, $body);
            //               $sign = json_decode($signature);
            //               $signature = $sign -> signature;
            //               $appid = $sign -> appid;          
                        
            //               $url = "https://edtsapp.indomaretpoinku.com/loyalty/apix0107x/mobile/v2/points/me/coupons/exchange";
            //               $headers = createHeaders($deviceId, $signature, $appid, $token);
            //               $response = curl($url, $body, $headers, "POST");
            //               echo $response . n ;
            //               $json = json_decode($response, true);
            //               $msg = $json['message'];
            //               if($msg == "Success") {
            //                 echo sp . hijau . 'No Hp      : ' . kuning . $nomor . n ;
            //                 echo sp . hijau . 'Nama kupon : ' . kuning . $selectedName . n ;
            //                 echo sp . hijau . 'Keterangan : ' . kuning . $msg . n ;
            //                 echo putih . garis . n . n ;
            //               }
            //     }
        
            //     } else {
            //         echo merah . "Nomor urut tidak valid.\n";
            //         goto pilihkupone;  
            //     }
       break;                 
    }
    
    case '11' :
        // $file = pilihFile("File_Akun");
        // $lines = file($file, FILE_IGNORE_NEW_LINES);
        // $no = 0;
        // foreach ($lines as $line_num => $line) {
        //     $akunxx1= explode('|', trim($line));
        //     $nomore = trim($akunxx1[0]);
        //     $index = $no + 1;
        //     $format = $index < 100 ? "[ %2d ]" : "[ %2d ]";  
        //     printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        // $no++;
        // }

        // echo "\n";
        // echo "\033[93;1mStart baris ke    : \033[96;1m";
        // $start = trim(fgets(STDIN));
        // echo "\033[93;1mSampai baris ke   : \033[96;1m";
        // $endd = trim(fgets(STDIN));
        // $filex = retrieveText($file, $start, $endd);
        // $list = explode("\n", str_replace("\r", "", $filex));
        // $no = $start;
        // foreach ($list as $kode) {
        //     if (empty($kode)) {
        //         continue;
        //     }

        // $akunxx = explode('|', trim($kode));
        // $nomor = trim($akunxx[0]);
        // $deviceId = trim($akunxx[1]);
        // $token = trim($akunxx[2]);

        //   $url = "https://edtsapp.indomaretpoinku.com/loyalty/apix0107x/mobile/v2/stamps/me/buckets?page=0&sort=balance%2Cdesc&sort=name%2Casc&size=1000";
        //   $signature = SignatureService::signature($nomor, $deviceId);
        //   $sign = json_decode($signature);
        //   $signature = $sign -> signature;
        //   $appid = $sign -> appid;          
        //   $headers = createHeaders($deviceId, $signat, $appid, $token);
        //   $response = curl($url, null, $headers, "GET");
        //   echo $appid . n . n;
        //   $json = json_decode($response, true);
        //   $content = $json['data']['content'];
        //   $i = 1; 
          
        //   foreach ($content as $item) {
        //       $pointExchangeId = $item['pointExchangeId'];
        //       $balance = $item['balance'];
        //       $amount = str_pad($amount, 18, " ", STR_PAD_BOTH);
        //       $id = $item['id'];
        //       $name = $item['name'];
        //       $namex = str_pad(mb_substr($name, 0, 55, 'UTF-8'), 55, " ", STR_PAD_RIGHT);
          
        //       if ($balance != '0') {
        //           $iFormatted = str_pad($i, 4, " ", STR_PAD_BOTH);  
        //           echo kuning . '┃ ' . biru . $iFormatted . kuning . ' ┃ ' . hijau . $namex . kuning . '┃ ' . biru . $amount . kuning . ' ┃ ' . biru . $sisakuota . kuning . ' ┃' . n;
          
        //           $names[$i] = $name;
        //           $i++; 
        //       }
        //   }

        // }
break;

    case '12':
        $folderPath = 'Kupon';
            $no = 0;

            if (is_dir($folderPath)) {
                $files = scandir($folderPath);
                foreach ($files as $file) {
                    if ($file != "." && $file != "..") {
                        $filePath = $folderPath . '/' . $file;
                        if (is_file($filePath)) {
                            $lineCount = count(file($filePath));
                            $unwantedWords = array(".txt", "!");
                            $file = str_replace($unwantedWords, "", $file);
                            $file = preg_replace("/\([^)]+\)/", "", $file);
                            $no = str_pad($no . ".", 3, " ");
                            $lineCount = str_pad($lineCount, 5, " ");
                            $file = substr($file, 0, 120);
                            $file = str_pad($file, 120, " ");
                            echo " $no \033[93;1m▶ \033[92;1m$file:   \033[97;1m$lineCount \033[96;1mkupon\n";
                            $no++;
                        }
                        
                    }
                }
            } else {
                echo "Folder '$folderPath' tidak ditemukan.\n";
            }

            break;


    case '13':

        $file = 'tokenbot.txt';
        if (file_exists($file)) {
            $lines = file($file, FILE_IGNORE_NEW_LINES);
        
            if (count($lines) > 0) {
                $line = $lines[0];
                $columns = explode('|', $line);
                if (count($columns) == 2) {
                    $bottoken = trim($columns[1]);
                    $owner = trim($columns[0]);
                } else {
                    echo merah . "Format file tidak sesuai. Pastikan file terdiri dari dua kolom yang dipisahkan oleh '|'.\n";
                }
            } else {
                echo merah . "File $file kosong.\n";
            }
        } else {
            echo "File $file tidak ditemukan.\n";
            echo kuning . "Masukkan nama owner: " . putih ;
            $owner = trim(fgets(STDIN)); 
            echo kuning . "Masukkan bot token : ". putih ;
            $bottoken = trim(fgets(STDIN)); 
            $data = $owner . '|' . $bottoken;
            file_put_contents($file, $data);
        
            echo hijau . "Data telah disimpan ke dalam file $file.\n";
        }
        $token = $bottoken;
        $bot = new BotApi($token);
        $client = new Client();

        $file = pilihFile("File_Akun"); 
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); 
        $validnomors = [];

        foreach ($lines as $index => $line) {
            $akunxx = explode('|', trim($line)); 
            $nomor = trim($akunxx[0]);
            $token = trim($akunxx[2]);
            if (!empty($nomor)) {
                $validnomors[$index + 1] = $nomor; 
            }
        }
        echo hijau . 'BOT SEDANG BERJALAN' . n ;
        $userStates = [];
        $offset = null;

        while (true) {
            try {
                $updates = $bot->getUpdates($offset);
        
                foreach ($updates as $update) {
                    $message = $update->getMessage();
                    $chatId = $message->getChat()->getId();
                    $text = trim($message->getText());
        
                    if ($text === "/start") {
                        $bot->sendMessage($chatId, "Selamat datang ! Ketik angka 1 - 10000 untuk menampilkan barcode member.");
                    } else {
                      $userStates[$chatId] = 'awaitingMenuChoice';
                      handlenomorInput($chatId, $text);
                  }        
                    $offset = $update->getUpdateId() + 1;
                }    
                sleep(1);
            } catch (Exception $e) {
                
                echo 'Error: ' . $e->getMessage() . PHP_EOL;
            }
        }

    break;

    case '14' :
        // $file = pilihFile("File_Akun");
        // $lines = file($file, FILE_IGNORE_NEW_LINES);
        // $no = 0;
        // foreach ($lines as $line_num => $line) {
        //     $akunxx1= explode('|', trim($line));
        //     $nomore = trim($akunxx1[0]);
        //     $index = $no + 1;
        //     $format = $index < 100 ? "[ %2d ]" : "[ %2d ]";  
        //     printf("\033[93;1m$format \033[92;1m%s\n", $index, $nomore);
        // $no++;
        // }

        // echo "\n";
        // echo "\033[93;1mStart baris ke    : \033[96;1m";
        // $start = trim(fgets(STDIN));
        // echo "\033[93;1mSampai baris ke   : \033[96;1m";
        // $endd = trim(fgets(STDIN));
        // $filex = retrieveText($file, $start, $endd);
        // $list = explode("\n", str_replace("\r", "", $filex));
        // $no = $start;
        // foreach ($list as $kode) {
        //     if (empty($kode)) {
        //         continue;
        //     }

        // $akunxx = explode('|', trim($kode));
        // $nomor = trim($akunxx[0]);
        // $deviceId = trim($akunxx[1]);
        // $token = trim($akunxx[2]);

        // $data = array(
        //     "couponId" => $selectedCouponId,
        //     "pointExchangeId" => $selectedPointExchangeId,
        //     "qty" => 1.0
        //         );
        // $body = json_encode($data);
        // $signature = SignatureService::signature($nomor, $body);
        // $sign = json_decode($signature);
        // $signature = $sign -> signature;
        // $appid = $sign -> appid;          
                        

        // }


}
goto awal;



function nama()
{
    $fname = array(
        'Abyasa', 'Ade', 'Adhiarja', 'Adiarja', 'Adika', 'Adikara', 'Adinata', 'Aditya', 'Agus', 'Ajiman', 
        'Ajimat', 'Ajimin', 'Ajiono', 'Akarsana', 'Alambana', 'Among', 'Anggabaya', 'Anom', 'Argono', 'Aris',
        'Arta', 'Artanto', 'Artawan', 'Arsipatra', 'Asirwada', 'Asirwanda', 'Aslijan', 'Asmadi', 'Asman',
        'Asmianto', 'Asmuni', 'Aswani', 'Atma', 'Atmaja', 'Bagas', 'Bagiya', 'Bagus', 'Bagya', 'Bahuraksa',
        'Bahuwarna', 'Bahuwirya', 'Bajragin', 'Bakda', 'Bakiadi', 'Bakianto', 'Bakidin', 'Bakijan', 'Bakiman',
        'Bakiono', 'Bakti', 'Baktiadi', 'Baktianto', 'Baktiono', 'Bala', 'Balamantri', 'Balangga', 'Balapati',
        'Balidin', 'Balijan', 'Bambang', 'Banara', 'Banawa', 'Banawi', 'Bancar', 'Budi', 'Cagak', 'Cager',
        'Cahyadi', 'Cahyanto', 'Cahya', 'Cahyo', 'Cahyono', 'Caket', 'Cakrabirawa', 'Cakrabuana', 'Cakrajiya',
        'Cakrawala', 'Cakrawangsa', 'Candra', 'Chandra', 'Candrakanta', 'Capa', 'Caraka', 'Carub', 'Catur',
        'Caturangga', 'Cawisadi', 'Cawisono', 'Cawuk', 'Cayadi', 'Cecep', 'Cemani', 'Cemeti', 'Cemplunk',
        'Cengkal', 'Cengkir', 'Dacin', 'Dadap', 'Dadi', 'Dagel', 'Daliman', 'Dalimin', 'Daliono', 'Damar',
        'Damu', 'Danang', 'Daniswara', 'Danu', 'Danuja', 'Dariati', 'Darijan', 'Darimin', 'Darmaji', 'Darman',
        'Darmana', 'Darmanto', 'Darsirah', 'Dartono', 'Daru', 'Daruna', 'Daryani', 'Dasa', 'Digdaya', 'Dimas',
        'Dimaz', 'Dipa', 'Dirja', 'Drajat', 'Dwi', 'Dono', 'Dodo', 'Edi', 'Eka', 'Elon', 'Eluh', 'Eman',
        'Emas', 'Embuh', 'Emong', 'Empluk', 'Endra', 'Enteng', 'Estiawan', 'Estiono', 'Eko', 'Edi', 'Edison',
        'Edward', 'Elvin', 'Erik', 'Emil', 'Ega', 'Emin', 'Eja', 'Gada', 'Gadang', 'Gaduh', 'Gaiman', 'Galak',
        'Galang', 'Galar', 'Galih', 'Galiono', 'Galuh', 'Galur', 'Gaman', 'Gamani', 'Gamanto', 'Gambira', 'Gamblang',
        'Ganda', 'Gandewa', 'Gandi', 'Gandi', 'Ganep', 'Gangsa', 'Gangsar', 'Ganjaran', 'Gantar', 'Gara', 'Garan',
        'Garang', 'Garda', 'Gatot', 'Gatra', 'Gilang', 'Galih', 'Ghani', 'Gading', 'Hairyanto', 'Hardana', 'Hardi',
        'Harimurti', 'Harja', 'Harjasa', 'Harjaya', 'Harjo', 'Harsana', 'Harsanto', 'Harsaya', 'Hartaka', 'Hartana',
        'Harto', 'Hasta', 'Heru', 'Himawan', 'Hadi', 'Halim', 'Hasim', 'Hasan', 'Hendra', 'Hendri', 'Heryanto',
        'Hamzah', 'Hari', 'Imam', 'Indra', 'Irwan', 'Irsad', 'Ikhsan', 'Irfan', 'Ian', 'Ibrahim', 'Ibrani', 'Ismail',
        'Irnanto', 'Ilyas', 'Ibun', 'Ivan', 'Ikin', 'Ihsan', 'Jabal', 'Jaeman', 'Jaga', 'Jagapati', 'Jagaraga',
        'Jail', 'Jaiman', 'Jaka', 'Jarwa', 'Jarwadi', 'Jarwi', 'Jasmani', 'Jaswadi', 'Jati', 'Jatmiko', 'Jaya',
        'Jayadi', 'Jayeng', 'Jinawi', 'Jindra', 'Joko', 'Jumadi', 'Jumari', 'Jamal', 'Jamil', 'Jais', 'Jefri',
        'Johan', 'Jono', 'Kacung', 'Kajen', 'Kambali', 'Kamidin', 'Kariman', 'Karja', 'Karma', 'Karman', 'Karna',
        'Karsa', 'Karsana', 'Karta', 'Kasiran', 'Kasusra', 'Kawaca', 'Kawaya', 'Kayun', 'Kemba', 'Kenari', 'Kenes',
        'Kuncara', 'Kunthara', 'Kusuma', 'Kadir', 'Kala', 'Kalim', 'Kurnia', 'Kanda', 'Kardi', 'Karya', 'Kasim',
        'Kairav', 'Kenzie', 'Kemal', 'Kamal', 'Koko', 'Labuh', 'Laksana', 'Lamar', 'Lanang', 'Langgeng', 'Lanjar',
        'Lantar', 'Lega', 'Legawa', 'Lembah', 'Liman', 'Limar', 'Luhung', 'Lukita', 'Luluh', 'Lulut', 'Lurhur',
        'Luwar', 'Luwes', 'Latif', 'Lasmanto', 'Lukman', 'Luthfi', 'Leo', 'Luis', 'Lutfan', 'Lasmono', 'Laswi',
        'Mahesa', 'Makara', 'Makuta', 'Manah', 'Maras', 'Margana', 'Mariadi', 'Marsudi', 'Martaka', 'Martana',
        'Martani', 'Marwata', 'Maryadi', 'Maryanto', 'Mitra', 'Mujur', 'Mulya', 'Mulyanto', 'Mulyono', 'Mumpuni',
        'Muni', 'Mursita', 'Murti', 'Mustika', 'Maman', 'Mahmud', 'Mahdi', 'Mahfud', 'Malik', 'Muhammad', 'Mustofa',
        'Marsito', 'Mursinin', 'Nalar', 'Naradi', 'Nardi', 'Niyaga', 'Nrima', 'Nugraha', 'Nyana', 'Narji', 'Nasab',
        'Nasrullah', 'Nasim', 'Najib', 'Najam', 'Nyoman', 'Olga', 'Ozy', 'Omar', 'Opan', 'Oskar', 'Oman', 'Okto',
        'Okta', 'Opung', 'Paiman', 'Panca', 'Pangeran', 'Pangestu', 'Pardi', 'Parman', 'Perkasa', 'Praba', 'Prabu',
        'Prabawa', 'Prabowo', 'Prakosa', 'Pranata', 'Pranawa', 'Prasetya', 'Prasetyo', 'Prayitna', 'Prayoga', 'Prayogo',
        'Purwadi', 'Purwa', 'Purwanto', 'Panji', 'Pandu', 'Paiman', 'Prima', 'Putu', 'Raden', 'Raditya', 'Raharja',
        'Rama', 'Rangga', 'Reksa', 'Respati', 'Rusman', 'Rosman', 'Rahmat', 'Rahman', 'Rendy', 'Reza', 'Rizki', 'Ridwan',
        'Rudi', 'Raden', 'Radit', 'Radika', 'Rafi', 'Rafid', 'Raihan', 'Salman', 'Saadat', 'Saiful', 'Surya', 'Slamet',
        'Samsul', 'Soleh', 'Simon', 'Sabar', 'Sabri', 'Sidiq', 'Satya', 'Setya', 'Saka', 'Sakti', 'Taswir', 'Tedi',
        'Teguh', 'Tenggono', 'Tompel', 'Teguh', 'Tumurun', 'Tulus', 'Tanto', 'Trisno', 'Tina', 'Tomi', 'Tulang', 'Tuty',
        'Tiyo', 'Udin', 'Utama', 'Umar', 'Uti', 'Udin', 'Wahyu', 'Widi', 'Widodo', 'Wahyu', 'Wahyu', 'Wilangga',
        'Wira', 'Wisman', 'Wirawan', 'Wijaya', 'Widi', 'Widiantoro', 'Yani', 'Yasin', 'Yunus', 'Yudha', 'Yudhi',
        'Yulian', 'Yulianto', 'Yulius', 'Yudistira', 'Yudistirawati', 'Zaki', 'Zainal', 'Zulfi', 'Zaid'
    );

    $lname = array(
        'Agustina', 'Andriani', 'Anggraini', 'Aryani', 'Astuti', 'Fujiati', 'Farida', 'Handayani', 'Hassanah', 
        'Hartati', 'Hasanah', 'Haryanti', 'Hariyah', 'Hastuti', 'Halimah', 'Kusmawati', 'Kuswandari', 'Laksmiwati',
        'Laksita', 'Lestari', 'Lailasari', 'Mandasari', 'Mardhiyah', 'Mayasari', 'Melani', 'Mulyani', 'Maryati',
        'Nurani', 'Nurul', 'Novianti', 'Ningsih', 'Putri', 'Ratna', 'Rini', 'Rachmawati', 'Sari', 'Siti', 'Suwanti',
        'Tami', 'Tania', 'Trisnawati', 'Wulandari', 'Yuliani', 'Yuniati', 'Zulaika', 'Zahra', 'Zainab'
    );
    $randomFirstName = $fname[array_rand($fname)];
    $randomLastName = $lname[array_rand($lname)];

    return $randomFirstName . ' ' . $randomLastName;
}

