package io.lombocska.app.web;

import io.lombocska.app.account.AccountService;
import io.lombocska.app.authorization.IsAdmin;
import io.lombocska.app.authorization.IsEditor;
import io.lombocska.app.authorization.IsUser;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Pages protégées. Chaque règle est déclarative ; l'ancien test impératif de ROLE_ADMIN
 * a disparu au profit d'une page dédiée, ce qui permet d'y appliquer la MFA par URL.
 */
@Controller
public class AccountController {

	private final AccountService accounts;

	public AccountController(AccountService accounts) {
		this.accounts = accounts;
	}

	@GetMapping("/")
	public String index() {
		return "index";
	}

	@IsUser
	@GetMapping("/user")
	public String user() {
		return "user-page";
	}

	@IsEditor
	@GetMapping("/content-editor")
	public String editor() {
		return "editor-page";
	}

	/** Son propre compte : tout utilisateur authentifié. */
	@GetMapping("/account")
	public String account(Authentication authentication, Model model) {
		model.addAttribute("account", this.accounts.findByEmail(authentication.getName()).orElse(null));
		return "account-page";
	}

	/** Liste de tous les comptes : ROLE_ADMIN et deux facteurs (voir SecurityConfiguration). */
	@IsAdmin
	@GetMapping("/administration/accounts")
	public String administration(Model model) {
		model.addAttribute("accounts", this.accounts.findAll());
		return "administration-page";
	}

}
