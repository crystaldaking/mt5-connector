<?php
namespace CrystalApps\Mt5Connector;
/**
 * Class Client
 * @package CrystalApps\Mt5Connector
 * @property \GuzzleHttp\Client $httpClient
 */
class Client
{
    private $ip;
    private $port;
    private $login;
    private $password;
    private $agent;
    private $httpClient;
    private $build;

    public function __construct($ip,$port,$login,$password,$agent,$build)
    {
        $this->ip = $ip;
        $this->port = $port;
        $this->login = $login;
        $this->password = $password;
        $this->agent = $agent;
        $this->build = $build;
    }

    /**
     * Define connection
     * @return bool
     */
    public function Connect()
    {
        $this->httpClient = new \GuzzleHttp\Client(
            [
                'base_uri' => $this->ip.':'.$this->port,
                'timeout' => 36000,
                'verify' => false,
            ]
        );

        return true;
    }

    public function Auth()
    {
        if ($this->httpClient == null) {
            return false;
        }

        $params = [
            'version' => $this->build,
            'agent' => $this->agent,
            'login' => $this->login,
            'type' => 'manager'
        ];

        $result = $this->httpClient->get('/auth_start',['query' => $params]);

        if ($result->getStatusCode() != 200){
            return ['Status' => 'Error code: '.$result->getStatusCode()];
        }

        $result = json_decode($result->getBody(),true);

        if ($result['retcode'] != '0 Done'){
            return ['Status' => 'Auth start error '.$result['retcode']];
        }

        /**
         * MT5 Psyhodelic
         */
        $srv_rand = hex2bin($result['srv_rand']);
        $password_hash = md5(mb_convert_encoding($this->password,'utf-16le','utf-8'),true).'WebAPI';
        $srv_rand_answer = md5(md5($password_hash,true).$srv_rand);
        $cli_rand_buf = random_bytes(16);
        $cli_rand = bin2hex($cli_rand_buf);

        /**
         * Send anwser
         */
        $params = [
            'srv_rand_answer' => $srv_rand_answer,
            'cli_rand' => $cli_rand
        ];

        $result = $this->httpClient->get('/auth_answer',['query' => $params]);

        if ($result->getStatusCode() != 200){
            return ['Status' => 'Error code: '.$result->getStatusCode()];
        }

        $result = json_decode($result->getBody(),true);

        if ($result['retcode'] != '0 Done'){
            return ['Status' => 'Auth start error '.$result['retcode']];
        }

        /**
         * Calculating the correct server response for a random client sequence
         */
        $cliRandAnswer = md5(md5($password_hash,true).$cli_rand_buf);

        if ($cliRandAnswer != $result['cli_rand_answer']){
            return ['Status' => 'Auth answer error: rand buffs missmatch'];
        }

        return ['Status' => 'OK'];
    }
}