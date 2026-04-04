<?php
/**
 * Base Model
 * Provides a shared PDO instance to all models.
 */
abstract class Model
{
    protected PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }
}
