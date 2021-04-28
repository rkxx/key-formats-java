package com.danubetech.keyformats.jose;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;

import java.util.Map;

public class JWK {
    private String kid;
    private String use;
    private String kty;
    private String crv;
    private String x;
    private String y;
    private String d;

    public JWK() {
    }

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static JWK parse(Map<String, Object> json) {
        return objectMapper.convertValue(json, JWK.class);
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getX() {
        return x;
    }

    public byte[] getXdecoded() {
        String x = this.getX();
        return x != null ? Base64.decodeBase64(x) : null;
    }

    public void setX(String x) {
        this.x = x;
    }

    public String getY() {
        return y;
    }

    public byte[] getYdecoded() {
        String y = this.getY();
        return y != null ? Base64.decodeBase64(y) : null;
    }

    public void setY(String y) {
        this.y = y;
    }

    public String getD() {
        return d;
    }

    public void setD(String d) {
        this.d = d;
    }

    public byte[] getDdecoded() {
        String d = this.getD();
        return d != null ? Base64.decodeBase64(d) : null;
    }
}
