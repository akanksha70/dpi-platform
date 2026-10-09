package com.akanksha.dpi.service.api;

import com.akanksha.dpi.service.TestSupport;
import com.akanksha.dpi.service.job.JobService;
import com.akanksha.dpi.service.rules.BlockRuleRepository;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
class RuleApiIntegrationTest {

    @Autowired
    private WebApplicationContext context;
    @Autowired
    private BlockRuleRepository repository;
    @Autowired
    private JobService jobs;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        repository.deleteAll();   // every test starts with an empty rules table
        mvc = MockMvcBuilders.webAppContextSetup(context).build();
    }

    private ResultActions createRule(String json) throws Exception {
        return mvc.perform(post("/api/rules").contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private String uploadAndWait(String... params) throws Exception {
        MockMultipartFile sample = new MockMultipartFile("file", "test_dpi.pcap",
                "application/octet-stream", TestSupport.samplePcap());
        var request = multipart("/api/analyses").file(sample);
        for (int i = 0; i + 1 < params.length; i += 2) {
            request.param(params[i], params[i + 1]);
        }
        MvcResult result = mvc.perform(request).andExpect(status().isAccepted()).andReturn();
        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.id");
        TestSupport.awaitFinished(jobs, id);
        return id;
    }

    @Test
    void createListAndDeleteRules() throws Exception {
        MvcResult created = createRule("{\"type\":\"app\",\"value\":\" twitter \"}")
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.type").value("APP"))
                .andExpect(jsonPath("$.value").value("Twitter/X"))
                .andReturn();
        Number id = JsonPath.read(created.getResponse().getContentAsString(), "$.id");

        mvc.perform(get("/api/rules"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)));

        mvc.perform(delete("/api/rules/" + id.longValue())).andExpect(status().isNoContent());

        mvc.perform(get("/api/rules")).andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void duplicateRuleIsRejected() throws Exception {
        createRule("{\"type\":\"APP\",\"value\":\"twitter\"}").andExpect(status().isCreated());
        // Different spelling, same rule once normalized:
        createRule("{\"type\":\"app\",\"value\":\"Twitter/X\"}").andExpect(status().isConflict());

        mvc.perform(get("/api/rules")).andExpect(jsonPath("$", hasSize(1)));
    }

    @Test
    void invalidRulesAreRejected() throws Exception {
        createRule("{\"type\":\"bogus\",\"value\":\"x.com\"}").andExpect(status().isBadRequest());
        createRule("{\"type\":\"IP\",\"value\":\"999.1.1.1\"}").andExpect(status().isBadRequest());
        createRule("{\"type\":\"APP\",\"value\":\"NotAnApp\"}").andExpect(status().isBadRequest());
        createRule("{\"type\":\"DOMAIN\",\"value\":\"   \"}").andExpect(status().isBadRequest());
        createRule("{\"value\":\"x.com\"}").andExpect(status().isBadRequest());
        createRule("this is not json").andExpect(status().isBadRequest());

        mvc.perform(get("/api/rules")).andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void deletingAnUnknownRuleReturns404() throws Exception {
        mvc.perform(delete("/api/rules/999999")).andExpect(status().isNotFound());
    }

    @Test
    void storedRulesApplyToNewAnalyses() throws Exception {
        createRule("{\"type\":\"APP\",\"value\":\"Twitter/X\"}").andExpect(status().isCreated());

        // No rules in the upload itself: the stored rule is applied automatically.
        String withStored = uploadAndWait();
        mvc.perform(get("/api/analyses/" + withStored))
                .andExpect(jsonPath("$.rules.blockApps", hasItem("Twitter/X")));
        mvc.perform(get("/api/analyses/" + withStored + "/report"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dropped", greaterThan(0)));

        // Opting out of stored rules.
        String without = uploadAndWait("applyStoredRules", "false");
        mvc.perform(get("/api/analyses/" + without))
                .andExpect(jsonPath("$.rules.blockApps", hasSize(0)));
        mvc.perform(get("/api/analyses/" + without + "/report"))
                .andExpect(jsonPath("$.dropped").value(0));
    }
}