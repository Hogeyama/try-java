/*
 * This file is generated by jOOQ.
 */
package com.example.demo.jooq.tables;


import com.example.demo.jooq.Keys;
import com.example.demo.jooq.Public;
import com.example.demo.jooq.tables.records.UserRolesRecord;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.UUID;

import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.Name;
import org.jooq.PlainSQL;
import org.jooq.QueryPart;
import org.jooq.SQL;
import org.jooq.Schema;
import org.jooq.Select;
import org.jooq.Stringly;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.UniqueKey;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class UserRoles extends TableImpl<UserRolesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>public.user_roles</code>
     */
    public static final UserRoles USER_ROLES = new UserRoles();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<UserRolesRecord> getRecordType() {
        return UserRolesRecord.class;
    }

    /**
     * The column <code>public.user_roles.user_id</code>.
     */
    public final TableField<UserRolesRecord, UUID> USER_ID = createField(DSL.name("user_id"), SQLDataType.UUID.nullable(false), this, "");

    /**
     * The column <code>public.user_roles.role_id</code>.
     */
    public final TableField<UserRolesRecord, UUID> ROLE_ID = createField(DSL.name("role_id"), SQLDataType.UUID.nullable(false), this, "");

    /**
     * The column <code>public.user_roles.created_at</code>.
     */
    public final TableField<UserRolesRecord, OffsetDateTime> CREATED_AT = createField(DSL.name("created_at"), SQLDataType.TIMESTAMPWITHTIMEZONE(6).nullable(false).defaultValue(DSL.field(DSL.raw("CURRENT_TIMESTAMP"), SQLDataType.TIMESTAMPWITHTIMEZONE)), this, "");

    private UserRoles(Name alias, Table<UserRolesRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private UserRoles(Name alias, Table<UserRolesRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>public.user_roles</code> table reference
     */
    public UserRoles(String alias) {
        this(DSL.name(alias), USER_ROLES);
    }

    /**
     * Create an aliased <code>public.user_roles</code> table reference
     */
    public UserRoles(Name alias) {
        this(alias, USER_ROLES);
    }

    /**
     * Create a <code>public.user_roles</code> table reference
     */
    public UserRoles() {
        this(DSL.name("user_roles"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : Public.PUBLIC;
    }

    @Override
    public UniqueKey<UserRolesRecord> getPrimaryKey() {
        return Keys.USER_ROLES_PKEY;
    }

    @Override
    public UserRoles as(String alias) {
        return new UserRoles(DSL.name(alias), this);
    }

    @Override
    public UserRoles as(Name alias) {
        return new UserRoles(alias, this);
    }

    @Override
    public UserRoles as(Table<?> alias) {
        return new UserRoles(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public UserRoles rename(String name) {
        return new UserRoles(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public UserRoles rename(Name name) {
        return new UserRoles(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public UserRoles rename(Table<?> name) {
        return new UserRoles(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public UserRoles where(Condition condition) {
        return new UserRoles(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public UserRoles where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public UserRoles where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public UserRoles where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public UserRoles where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public UserRoles where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public UserRoles where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public UserRoles where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public UserRoles whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public UserRoles whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
