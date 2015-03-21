<?php
class SilverStripeSQRLRequestHandler extends Trianglman\Sqrl\SqrlRequestHandler {
    protected function login($continue) {
        $response=parent::login($continue);
        
        if($response==(self::COMMAND_FAILED|self::IP_MATCH)) {
        }
        
        return $response;
    }
}
?>