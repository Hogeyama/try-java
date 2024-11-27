/*
 * This file is generated by jOOQ.
 */
package com.example.demo.jooq.tables.records;


import com.example.demo.jooq.tables.Users;

import java.time.OffsetDateTime;
import java.util.UUID;

import org.jooq.Record1;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class UsersRecord extends UpdatableRecordImpl<UsersRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>public.users.id</code>.
     */
    public UsersRecord setId(UUID value) {
        set(0, value);
        return this;
    }

    /**
     * Getter for <code>public.users.id</code>.
     */
    public UUID getId() {
        return (UUID) get(0);
    }

    /**
     * Setter for <code>public.users.username</code>.
     */
    public UsersRecord setUsername(String value) {
        set(1, value);
        return this;
    }

    /**
     * Getter for <code>public.users.username</code>.
     */
    public String getUsername() {
        return (String) get(1);
    }

    /**
     * Setter for <code>public.users.password</code>.
     */
    public UsersRecord setPassword(String value) {
        set(2, value);
        return this;
    }

    /**
     * Getter for <code>public.users.password</code>.
     */
    public String getPassword() {
        return (String) get(2);
    }

    /**
     * Setter for <code>public.users.email</code>.
     */
    public UsersRecord setEmail(String value) {
        set(3, value);
        return this;
    }

    /**
     * Getter for <code>public.users.email</code>.
     */
    public String getEmail() {
        return (String) get(3);
    }

    /**
     * Setter for <code>public.users.enabled</code>.
     */
    public UsersRecord setEnabled(Boolean value) {
        set(4, value);
        return this;
    }

    /**
     * Getter for <code>public.users.enabled</code>.
     */
    public Boolean getEnabled() {
        return (Boolean) get(4);
    }

    /**
     * Setter for <code>public.users.created_at</code>.
     */
    public UsersRecord setCreatedAt(OffsetDateTime value) {
        set(5, value);
        return this;
    }

    /**
     * Getter for <code>public.users.created_at</code>.
     */
    public OffsetDateTime getCreatedAt() {
        return (OffsetDateTime) get(5);
    }

    /**
     * Setter for <code>public.users.updated_at</code>.
     */
    public UsersRecord setUpdatedAt(OffsetDateTime value) {
        set(6, value);
        return this;
    }

    /**
     * Getter for <code>public.users.updated_at</code>.
     */
    public OffsetDateTime getUpdatedAt() {
        return (OffsetDateTime) get(6);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    @Override
    public Record1<UUID> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached UsersRecord
     */
    public UsersRecord() {
        super(Users.USERS);
    }

    /**
     * Create a detached, initialised UsersRecord
     */
    public UsersRecord(UUID id, String username, String password, String email, Boolean enabled, OffsetDateTime createdAt, OffsetDateTime updatedAt) {
        super(Users.USERS);

        setId(id);
        setUsername(username);
        setPassword(password);
        setEmail(email);
        setEnabled(enabled);
        setCreatedAt(createdAt);
        setUpdatedAt(updatedAt);
        resetChangedOnNotNull();
    }

    /**
     * Create a detached, initialised UsersRecord
     */
    public UsersRecord(com.example.demo.jooq.tables.pojos.Users value) {
        super(Users.USERS);

        if (value != null) {
            setId(value.getId());
            setUsername(value.getUsername());
            setPassword(value.getPassword());
            setEmail(value.getEmail());
            setEnabled(value.getEnabled());
            setCreatedAt(value.getCreatedAt());
            setUpdatedAt(value.getUpdatedAt());
            resetChangedOnNotNull();
        }
    }
}
