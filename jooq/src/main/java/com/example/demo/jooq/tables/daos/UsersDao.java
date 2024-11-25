/*
 * This file is generated by jOOQ.
 */
package com.example.demo.jooq.tables.daos;


import com.example.demo.jooq.tables.Users;
import com.example.demo.jooq.tables.records.UsersRecord;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.jooq.Configuration;
import org.jooq.impl.DAOImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
@Repository
public class UsersDao extends DAOImpl<UsersRecord, com.example.demo.jooq.tables.pojos.Users, Long> {

    /**
     * Create a new UsersDao without any configuration
     */
    public UsersDao() {
        super(Users.USERS, com.example.demo.jooq.tables.pojos.Users.class);
    }

    /**
     * Create a new UsersDao with an attached configuration
     */
    @Autowired
    public UsersDao(Configuration configuration) {
        super(Users.USERS, com.example.demo.jooq.tables.pojos.Users.class, configuration);
    }

    @Override
    public Long getId(com.example.demo.jooq.tables.pojos.Users object) {
        return object.getId();
    }

    /**
     * Fetch records that have <code>id BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchRangeOfId(Long lowerInclusive, Long upperInclusive) {
        return fetchRange(Users.USERS.ID, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>id IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchById(Long... values) {
        return fetch(Users.USERS.ID, values);
    }

    /**
     * Fetch a unique record that has <code>id = value</code>
     */
    public com.example.demo.jooq.tables.pojos.Users fetchOneById(Long value) {
        return fetchOne(Users.USERS.ID, value);
    }

    /**
     * Fetch a unique record that has <code>id = value</code>
     */
    public Optional<com.example.demo.jooq.tables.pojos.Users> fetchOptionalById(Long value) {
        return fetchOptional(Users.USERS.ID, value);
    }

    /**
     * Fetch records that have <code>username BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchRangeOfUsername(String lowerInclusive, String upperInclusive) {
        return fetchRange(Users.USERS.USERNAME, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>username IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchByUsername(String... values) {
        return fetch(Users.USERS.USERNAME, values);
    }

    /**
     * Fetch a unique record that has <code>username = value</code>
     */
    public com.example.demo.jooq.tables.pojos.Users fetchOneByUsername(String value) {
        return fetchOne(Users.USERS.USERNAME, value);
    }

    /**
     * Fetch a unique record that has <code>username = value</code>
     */
    public Optional<com.example.demo.jooq.tables.pojos.Users> fetchOptionalByUsername(String value) {
        return fetchOptional(Users.USERS.USERNAME, value);
    }

    /**
     * Fetch records that have <code>password BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchRangeOfPassword(String lowerInclusive, String upperInclusive) {
        return fetchRange(Users.USERS.PASSWORD, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>password IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchByPassword(String... values) {
        return fetch(Users.USERS.PASSWORD, values);
    }

    /**
     * Fetch records that have <code>email BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchRangeOfEmail(String lowerInclusive, String upperInclusive) {
        return fetchRange(Users.USERS.EMAIL, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>email IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchByEmail(String... values) {
        return fetch(Users.USERS.EMAIL, values);
    }

    /**
     * Fetch a unique record that has <code>email = value</code>
     */
    public com.example.demo.jooq.tables.pojos.Users fetchOneByEmail(String value) {
        return fetchOne(Users.USERS.EMAIL, value);
    }

    /**
     * Fetch a unique record that has <code>email = value</code>
     */
    public Optional<com.example.demo.jooq.tables.pojos.Users> fetchOptionalByEmail(String value) {
        return fetchOptional(Users.USERS.EMAIL, value);
    }

    /**
     * Fetch records that have <code>enabled BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchRangeOfEnabled(Boolean lowerInclusive, Boolean upperInclusive) {
        return fetchRange(Users.USERS.ENABLED, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>enabled IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchByEnabled(Boolean... values) {
        return fetch(Users.USERS.ENABLED, values);
    }

    /**
     * Fetch records that have <code>created_at BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchRangeOfCreatedAt(OffsetDateTime lowerInclusive, OffsetDateTime upperInclusive) {
        return fetchRange(Users.USERS.CREATED_AT, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>created_at IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchByCreatedAt(OffsetDateTime... values) {
        return fetch(Users.USERS.CREATED_AT, values);
    }

    /**
     * Fetch records that have <code>updated_at BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchRangeOfUpdatedAt(OffsetDateTime lowerInclusive, OffsetDateTime upperInclusive) {
        return fetchRange(Users.USERS.UPDATED_AT, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>updated_at IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.Users> fetchByUpdatedAt(OffsetDateTime... values) {
        return fetch(Users.USERS.UPDATED_AT, values);
    }
}
