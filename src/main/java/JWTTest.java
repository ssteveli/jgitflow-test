import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.util.encoders.Hex;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


public class JWTTest {

    public static void main(String[] args) throws Exception {
        SecureRandom r = new SecureRandom();
        byte[] sharedSecret = new byte[16];
        r.nextBytes(sharedSecret);
        
        System.out.println(Hex.toHexString(sharedSecret));
        
        JWSSigner signer = new MACSigner(sharedSecret);
        
        JWTClaimsSet claims = new JWTClaimsSet();
        claims.setClaim("encryptedData", "123");
        claims.setClaim("createdTs", new Date());
        
        SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJwt.sign(signer);
        
        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM), new Payload(signedJwt));
        jwe.encrypt(new AESEncrypter(sharedSecret));
        
        String jwt = jwe.serialize();
        
        System.out.println(jwt);
    }
}
