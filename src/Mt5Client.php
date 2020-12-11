<?php
namespace CrystalApps\Mt5Connector;

use GuzzleHttp\RequestOptions;

/**
 * Class Client
 * @package CrystalApps\Mt5Connector
 * @property \GuzzleHttp\Client $httpClient
 */
class Mt5Client
{
    private $ip;
    private $port;
    private $login;
    private $password;
    private $agent;
    private $httpClient;
    private $build;

    public function __construct($ip, $port, $login, $password, $agent, $build)
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
                'base_uri' => $this->ip . ':' . $this->port,
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

        $result = $this->httpClient->get('/auth_start', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Error code: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'Auth start error ' . $result['retcode']];
        }

        /**
         * MT5 Psyhodelic
         */
        $srv_rand = hex2bin($result['srv_rand']);
        $password_hash = md5(mb_convert_encoding($this->password, 'utf-16le', 'utf-8'), true) . 'WebAPI';
        $srv_rand_answer = md5(md5($password_hash, true) . $srv_rand);
        $cli_rand_buf = random_bytes(16);
        $cli_rand = bin2hex($cli_rand_buf);

        /**
         * Send anwser
         */
        $params = [
            'srv_rand_answer' => $srv_rand_answer,
            'cli_rand' => $cli_rand
        ];

        $result = $this->httpClient->get('/auth_answer', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Error code: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'Auth start error ' . $result['retcode']];
        }

        /**
         * Calculating the correct server response for a random client sequence
         */
        $cliRandAnswer = md5(md5($password_hash, true) . $cli_rand_buf);

        if ($cliRandAnswer != $result['cli_rand_answer']) {
            return ['Status' => 'Auth answer error: rand buffs missmatch'];
        }

        return ['Status' => 'OK'];
    }

    /**
     * Update MT5 User
     * @param array $params
     */
    public function UserUpdate(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login'])) {
            return ['Status' => 'Login is emptry'];
        }

        $result = $this->httpClient->get('/user_update', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User update error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * Create MT5 User
     * @param array $params
     */
    public function UserAdd(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['pass_main']) || empty($params['pass_investor']) || empty($params['name']) || empty($params['group'])) {
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_add', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User create error ' . $result['retcode']];
        }

        /*if ($result['login'] == null){
            return ['Status' => 'Server error: login field is empty'];
        }*/

        return $result['answer'];
    }

    /**
     * Delete MT5 User
     * @param array $params
     */
    public function UserDelete(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login'])) {
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_delete', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User delete error ' . $result['retcode']];
        }

        return $result['retcode'];
    }

    /**
     * MT5 Users Get Batch
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserGetBatch(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login']) && empty($params['group'])) {
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_get_batch', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User get batch error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * MT5 User Pass check
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserPassCheck(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login']) || empty($params['password']) || empty($params['type'])) {
            return ['Status' => 'Missing requred fields'];
        }

        if ($params['type'] != 'main' && $params['type'] != 'investor' && $params['type'] != 'api') {
            return ['Status' => 'type field is incorrect'];
        }

        $result = $this->httpClient->get('/user_pass_check', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        return $result['retcode'];
    }

    /**
     * MT5 User Pass Change
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserPassChange(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login']) || empty($params['password']) || empty($params['type'])) {
            return ['Status' => 'Missing requred fields'];
        }

        if ($params['type'] != 'main' && $params['type'] != 'investor' && $params['type'] != 'api') {
            return ['Status' => 'type field is incorrect'];
        }

        $result = $this->httpClient->get('/user_pass_change', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        return $result['retcode'];
    }

    /**
     * MT5 User account get
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserAccountGet(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login'])) {
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_account_get', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User acoount get error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * MT5 User account get batch
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserAccountGetBatch(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login']) || empty($params['group'])) {
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_account_get_batch', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User acoount get batch error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * Get MT5 User logins by group
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserLogins(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['group'])) {
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_logins', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User logins get error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * Get MT5 total user count
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserTotal()
    {
        if ($this->httpClient == null) {
            return false;
        }

        $result = $this->httpClient->get('/user_total');

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User acoount get error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * Get MT5 User group get
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserGroup(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login'])) {
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_group', ['query' => $params]);

        if ($result->getStatusCode() != 200) {
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User group get error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * MT5 User balance check
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserBalanceCheck(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login']) && empty($params['fixflag'])){
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_balance_check',['query' => $params]);

        if ($result->getStatusCode() != 200){
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done') {
            return ['Status' => 'User balance check error ' . $result['retcode']];
        }

        return $result['answer'];
    }

    /** MT5 Archive user
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserArchive(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login'])){
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_archive',['query' => $params]);

        if ($result->getStatusCode() != 200){
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        return $result;
    }


    /**
     * User Archive get
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserArchiveGet(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['login'])){
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_archive_get',['query' => $params]);

        if ($result->getStatusCode() != 200){
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done'){
            return ['Status' => 'User archive get error'.$result['retcode']];
        }

        return $result['answer'];
    }

    /**
     * MT5 User backup get
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserBackupGet(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params['backup']) && empty($params['login'])){
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->get('/user_backup_get',['query' => $params]);

        if ($result->getStatusCode() != 200){
            return ['Status' => 'Server error: ' . $result->getStatusCode()];
        }

        $result = json_decode($result->getBody(), true);

        if ($result['retcode'] != '0 Done'){
            return ['Status' => 'User backup get error'.$result['retcode']];
        }

        unset($result['answer']['ApiData']);

        return $result['answer'];
    }


    /**
     * MT5 User Restore
     * @param array $params
     * @return false|mixed|string[]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function UserRestore(array $params)
    {
        if ($this->httpClient == null) {
            return false;
        }

        if (empty($params)){
            return ['Status' => 'Missing requred fields'];
        }

        $result = $this->httpClient->post('/user_restore',[RequestOptions::JSON => $params]);

        if ($result->getStatusCode() != 200){
            return ['Status' => 'Server error: '.$result->getStatusCode()];
        }

        $result = json_decode($result->getBody(),true);

        if ($result['retcode'] != '0 Done'){
            return ['Status' => 'User restore error'.$result['retcode']];
        }

        return $result['answer'];
    }
}