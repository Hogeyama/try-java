/*
 * This file is generated by jOOQ.
 */
package com.example.demo.jooq.tables.daos;


import com.example.demo.jooq.tables.RevokedTokens;
import com.example.demo.jooq.tables.records.RevokedTokensRecord;

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
public class RevokedTokensDao extends DAOImpl<RevokedTokensRecord, com.example.demo.jooq.tables.pojos.RevokedTokens, Long> {

    /**
     * Create a new RevokedTokensDao without any configuration
     */
    public RevokedTokensDao() {
        super(RevokedTokens.REVOKED_TOKENS, com.example.demo.jooq.tables.pojos.RevokedTokens.class);
    }

    /**
     * Create a new RevokedTokensDao with an attached configuration
     */
    @Autowired
    public RevokedTokensDao(Configuration configuration) {
        super(RevokedTokens.REVOKED_TOKENS, com.example.demo.jooq.tables.pojos.RevokedTokens.class, configuration);
    }

    @Override
    public Long getId(com.example.demo.jooq.tables.pojos.RevokedTokens object) {
        return object.getId();
    }

    /**
     * Fetch records that have <code>id BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchRangeOfId(Long lowerInclusive, Long upperInclusive) {
        return fetchRange(RevokedTokens.REVOKED_TOKENS.ID, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>id IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchById(Long... values) {
        return fetch(RevokedTokens.REVOKED_TOKENS.ID, values);
    }

    /**
     * Fetch a unique record that has <code>id = value</code>
     */
    public com.example.demo.jooq.tables.pojos.RevokedTokens fetchOneById(Long value) {
        return fetchOne(RevokedTokens.REVOKED_TOKENS.ID, value);
    }

    /**
     * Fetch a unique record that has <code>id = value</code>
     */
    public Optional<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchOptionalById(Long value) {
        return fetchOptional(RevokedTokens.REVOKED_TOKENS.ID, value);
    }

    /**
     * Fetch records that have <code>jti BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchRangeOfJti(String lowerInclusive, String upperInclusive) {
        return fetchRange(RevokedTokens.REVOKED_TOKENS.JTI, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>jti IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchByJti(String... values) {
        return fetch(RevokedTokens.REVOKED_TOKENS.JTI, values);
    }

    /**
     * Fetch a unique record that has <code>jti = value</code>
     */
    public com.example.demo.jooq.tables.pojos.RevokedTokens fetchOneByJti(String value) {
        return fetchOne(RevokedTokens.REVOKED_TOKENS.JTI, value);
    }

    /**
     * Fetch a unique record that has <code>jti = value</code>
     */
    public Optional<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchOptionalByJti(String value) {
        return fetchOptional(RevokedTokens.REVOKED_TOKENS.JTI, value);
    }

    /**
     * Fetch records that have <code>revoked_at BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchRangeOfRevokedAt(OffsetDateTime lowerInclusive, OffsetDateTime upperInclusive) {
        return fetchRange(RevokedTokens.REVOKED_TOKENS.REVOKED_AT, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>revoked_at IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchByRevokedAt(OffsetDateTime... values) {
        return fetch(RevokedTokens.REVOKED_TOKENS.REVOKED_AT, values);
    }

    /**
     * Fetch records that have <code>reason BETWEEN lowerInclusive AND
     * upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchRangeOfReason(String lowerInclusive, String upperInclusive) {
        return fetchRange(RevokedTokens.REVOKED_TOKENS.REASON, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>reason IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchByReason(String... values) {
        return fetch(RevokedTokens.REVOKED_TOKENS.REASON, values);
    }

    /**
     * Fetch records that have <code>created_by_user_id BETWEEN lowerInclusive
     * AND upperInclusive</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchRangeOfCreatedByUserId(Long lowerInclusive, Long upperInclusive) {
        return fetchRange(RevokedTokens.REVOKED_TOKENS.CREATED_BY_USER_ID, lowerInclusive, upperInclusive);
    }

    /**
     * Fetch records that have <code>created_by_user_id IN (values)</code>
     */
    public List<com.example.demo.jooq.tables.pojos.RevokedTokens> fetchByCreatedByUserId(Long... values) {
        return fetch(RevokedTokens.REVOKED_TOKENS.CREATED_BY_USER_ID, values);
    }
}