package zrouga.spring.security.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verrouillage de compte activé (seuil 3, verrou 60 s) : 423 {@code account_locked}
 * dès le 3e échec — même avec le bon mot de passe, même pour un compte inconnu —
 * et remise à zéro du compteur après une connexion réussie. Contexte isolé
 * (propriétés dédiées) pour ne pas polluer les autres tests.
 */
@SpringBootTest(properties = {
        "zrouga.security.lockout-enabled=true",
        "zrouga.security.lockout-max-attempts=3",
        "zrouga.security.lockout-duration-ms=60000"
})
@AutoConfigureMockMvc
class AccountLockoutIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private void signin(String email, String password, int expectedStatus) throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().is(expectedStatus));
    }

    @Test
    void compteVerrouilleApresTroisEchecsMemeAvecLeBonMotDePasse() throws Exception {
        String email = "lock-" + System.nanoTime() + "@test.com";

        signin(email, "mauvais-1", 401);
        signin(email, "mauvais-2", 401);

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"mauvais-3\"}"))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.status").value(423))
                .andExpect(jsonPath("$.code").value("account_locked"))
                .andExpect(jsonPath("$.error").value("Locked"))
                .andExpect(jsonPath("$.message").isNotEmpty());

        // Même une bonne combinaison e-mail/mot de passe reste refusée pendant le verrou
        // (le verrou est vérifié avant l'authentification).
        signin(email, "MotDePasse@123", 423);
    }

    @Test
    void compteInconnuSeVerrouilleUniformement() throws Exception {
        String email = "ghost-" + System.nanoTime() + "@test.com";

        signin(email, "mauvais-1", 401);
        signin(email, "mauvais-2", 401);
        signin(email, "mauvais-3", 423);

        // Aucune différence de comportement avec un compte existant (anti-énumération).
        signin(email, "EncoreMauvais!", 423);
    }

    @Test
    void connexionReussieRemetLeCompteurAEchecs() throws Exception {
        String email = "reset-" + System.nanoTime() + "@test.com";
        String password = "MotDePasse@123";

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isCreated());

        // 2 échecs, puis succès : le compteur repart de zéro.
        signin(email, "mauvais-1", 401);
        signin(email, "mauvais-2", 401);
        signin(email, password, 200);

        // Sans remise à zéro, ces 2 échecs atteindraient le seuil 3 → 423.
        signin(email, "mauvais-3", 401);
        signin(email, "mauvais-4", 401);
    }
}
