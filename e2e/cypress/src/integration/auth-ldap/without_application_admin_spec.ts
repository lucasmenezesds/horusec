describe("Horusec LDAP test", () => {
    it("Should login with ldap credentials", () => {
        cy.visit("http://localhost:8043/auth");
        cy.wait(4000);

        // Login with default account
        cy.get("#email").type("test");
        cy.get("#password").type("test");
        cy.get("button").first().click();
        cy.wait(1000);

        // Check if not exists workspace
        cy.contains("Add a new Workspace to start using Horusec.").should("exist");
    });
});
