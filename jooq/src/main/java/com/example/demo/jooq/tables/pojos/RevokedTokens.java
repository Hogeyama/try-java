/*
 * This file is generated by jOOQ.
 */
package com.example.demo.jooq.tables.pojos;


import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.UUID;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class RevokedTokens implements Serializable {

    private static final long serialVersionUID = 1L;

    private final UUID id;
    private final String jti;
    private final OffsetDateTime revokedAt;
    private final String reason;
    private final UUID createdByUserId;

    public RevokedTokens(RevokedTokens value) {
        this.id = value.id;
        this.jti = value.jti;
        this.revokedAt = value.revokedAt;
        this.reason = value.reason;
        this.createdByUserId = value.createdByUserId;
    }

    public RevokedTokens(
        UUID id,
        String jti,
        OffsetDateTime revokedAt,
        String reason,
        UUID createdByUserId
    ) {
        this.id = id;
        this.jti = jti;
        this.revokedAt = revokedAt;
        this.reason = reason;
        this.createdByUserId = createdByUserId;
    }

    /**
     * Getter for <code>public.revoked_tokens.id</code>.
     */
    public UUID getId() {
        return this.id;
    }

    /**
     * Getter for <code>public.revoked_tokens.jti</code>.
     */
    public String getJti() {
        return this.jti;
    }

    /**
     * Getter for <code>public.revoked_tokens.revoked_at</code>.
     */
    public OffsetDateTime getRevokedAt() {
        return this.revokedAt;
    }

    /**
     * Getter for <code>public.revoked_tokens.reason</code>.
     */
    public String getReason() {
        return this.reason;
    }

    /**
     * Getter for <code>public.revoked_tokens.created_by_user_id</code>.
     */
    public UUID getCreatedByUserId() {
        return this.createdByUserId;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        final RevokedTokens other = (RevokedTokens) obj;
        if (this.id == null) {
            if (other.id != null)
                return false;
        }
        else if (!this.id.equals(other.id))
            return false;
        if (this.jti == null) {
            if (other.jti != null)
                return false;
        }
        else if (!this.jti.equals(other.jti))
            return false;
        if (this.revokedAt == null) {
            if (other.revokedAt != null)
                return false;
        }
        else if (!this.revokedAt.equals(other.revokedAt))
            return false;
        if (this.reason == null) {
            if (other.reason != null)
                return false;
        }
        else if (!this.reason.equals(other.reason))
            return false;
        if (this.createdByUserId == null) {
            if (other.createdByUserId != null)
                return false;
        }
        else if (!this.createdByUserId.equals(other.createdByUserId))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((this.id == null) ? 0 : this.id.hashCode());
        result = prime * result + ((this.jti == null) ? 0 : this.jti.hashCode());
        result = prime * result + ((this.revokedAt == null) ? 0 : this.revokedAt.hashCode());
        result = prime * result + ((this.reason == null) ? 0 : this.reason.hashCode());
        result = prime * result + ((this.createdByUserId == null) ? 0 : this.createdByUserId.hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("RevokedTokens (");

        sb.append(id);
        sb.append(", ").append(jti);
        sb.append(", ").append(revokedAt);
        sb.append(", ").append(reason);
        sb.append(", ").append(createdByUserId);

        sb.append(")");
        return sb.toString();
    }
}
