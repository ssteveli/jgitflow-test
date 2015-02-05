import org.spongycastle.util.encoders.Hex;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;


public class JWEDecoder {

    public static void main(String[] args) throws Exception {
        byte[] sharedSecret = Hex.decode("db2a2634cbae7c01ea2d22797deb11da");
        JWEObject jwe = JWEObject.parse(
                "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.oGOP1SG2nx5rcj5dqNozojQsBfEAU1_G.Pn1f353rZiQ0FjRR.c7XL6Unc4FUoAHW8cwI-F0OMVd9FP0u94g3JwVv4d42048NfDQPqkv4hnOA_bc3WUdd1cVvWA0McRLUCaG6TAprEP4-w9tcz7LQBLXNGzUUZQmf2ES1gZaEpDPoWsZFMwwya6ktcHQalurXqNAsfMYazzgNxbpVxaLDL7sgKsV6GtdpRa-ssHNWD8qH7JUsdjLS6E7Xniruq.wAVVgxGcfjfvkKLn1Iv9fA"
        );
        jwe.decrypt(new AESDecrypter(sharedSecret));
        
        SignedJWT jwt = jwe.getPayload().toSignedJWT();
        
        System.out.println("signature verification: " + jwt.verify(new MACVerifier(sharedSecret)));
        System.out.println(jwt.getJWTClaimsSet().getClaim("encryptedData"));
        System.out.println(jwt.getJWTClaimsSet().getClaim("createdTs"));
    }
}
