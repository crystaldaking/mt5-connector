<?php
namespace CrystalApps\Mt5Connector;
class Client
{
    private $connection = null;
    private $ip = null;
    private $port = null;
    private $login = null;
    private $password = null;
    private $agent = null;
    private $httpClient = null;

    public function __construct($connection,$ip,$port,$login,$password,$agent)
    {
        $this->connection = $connection;
        $this->ip = $ip;
        $this->port = $port;
        $this->login = $login;
        $this->password = $password;
        $this->agent = $agent;
    }

    public function Connect()
    {
        $this->httpClient = new \GuzzleHttp\Client(
            [
                'base_uri' => $this->ip.':'.$this->port,
                'timeout' => 36000,
                'verify' => false,
            ]
        );
    }
}