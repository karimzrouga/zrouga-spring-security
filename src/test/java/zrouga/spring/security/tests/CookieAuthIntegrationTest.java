package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;

import com.jayway.jsonpath.JsonPath;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Mode {@code zrouga.security.auth-mode=cookie} (Stateful Session Cookies) :
 * cookies HttpOnly émis à la connexion, lus par le filtre et les endpoints,
 * réémis à chaque rotation, vidés à la déconnexion.
 */
@SpringBootTest(properties = {
        "zrouga.security.auth-mode=cookie",
        "zrouga.security.cookie-same-site=Strict",
        "zrouga.security.reset-enabled=true",
        "zrouga.security.reset-base-url=https://front.test/reset-password"
})
@AutoConfigureMockMvc
class CookieAuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private MvcResult signin() throws Exception {
        return mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();
    }

    private static Cookie cookie(MvcResult result, String name) {
        return Arrays.stream(result.getResponse().getCookies())
                .filter(c -> name.equals(c.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("cookie " + name + " absente de la réponse"));
    }

    private static String setCookie(MvcResult result, String name) {
        return result.getResponse().getHeaders("Set-Cookie").stream()
                .filter(h -> h.startsWith(name + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Set-Cookie " + name + " absente de la réponse"));
    }

    @Test
    void signinEmetLesDeuxCookiesHttpOnly() throws Exception {
        MvcResult result = signin();

        String access = setCookie(result, "zrouga_access");
        assertThat(access).contains("HttpOnly").contains("Path=/").contains("SameSite=Strict");

        String refresh = setCookie(result, "zrouga_refresh");
        assertThat(refresh).contains("HttpOnly").contains("Path=/api/auth").contains("SameSite=Strict");

        assertThat(cookie(result, "zrouga_access").getValue()).isNotBlank();
        assertThat(cookie(result, "zrouga_refresh").getValue()).isNotBlank();
    }

    @Test
    void endpointProtegeAccepteLaCookieAccessEtLeHeader() throws Exception {
        MvcResult result = signin();

        mockMvc.perform(get("/api/hello").cookie(cookie(result, "zrouga_access")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("hello"));

        // Coexistence : le header Bearer reste fonctionnel en mode cookie.
        mockMvc.perform(get("/api/hello")
                        .header("Authorization", "Bearer " + cookie(result, "zrouga_access").getValue()))
                .andExpect(status().isOk());
    }

    @Test
    void refreshtokenLitLaCookieEtReemetLesDeuxCookies() throws Exception {
        MvcResult signinResult = signin();
        String ancienRefresh = cookie(signinResult, "zrouga_refresh").getValue();

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .cookie(cookie(signinResult, "zrouga_refresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        String nouveauRefresh = cookie(refreshResult, "zrouga_refresh").getValue();
        assertThat(nouveauRefresh).isNotEqualTo(ancienRefresh);
        assertThat(setCookie(refreshResult, "zrouga_access")).contains("HttpOnly");
        assertThat(setCookie(refreshResult, "zrouga_refresh")).contains("Path=/api/auth");

        // L'ancien refresh tourne n'est plus valide (rotation).
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .cookie(new Cookie("zrouga_refresh", ancienRefresh)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message", containsString("not in database")));
    }

    @Test
    void refreshtokenSansCookieNiCorpsRenvoie403() throws Exception {
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("refresh_token_rejected"));
    }

    @Test
    void signoutVideLesDeuxCookies() throws Exception {
        MvcResult signinResult = signin();

        MvcResult signoutResult = mockMvc.perform(post("/api/auth/signout")
                        .cookie(cookie(signinResult, "zrouga_access")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Log out successful!"))
                .andReturn();

        assertThat(setCookie(signoutResult, "zrouga_access")).contains("Max-Age=0");
        assertThat(setCookie(signoutResult, "zrouga_refresh")).contains("Max-Age=0");
    }

    @Test
    void resetPasswordEchoueSansViderLesCookies() throws Exception {
        // La vidange des cookies n'a lieu qu'après succès : un reset invalide
        // laisse la session (cookies) intacte.
        MvcResult resetResult = mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"jeton-invalide\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(resetResult.getResponse().getHeaders("Set-Cookie")).isEmpty();
    }
}
