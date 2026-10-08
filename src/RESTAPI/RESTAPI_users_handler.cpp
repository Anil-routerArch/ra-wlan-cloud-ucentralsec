//
// Created by stephane bourque on 2021-06-21.
//

#include "RESTAPI_users_handler.h"
#include "ACLProcessor.h"
#include "RESTAPI/RESTAPI_db_helpers.h"
#include "AuthService.h"
#include "StorageService.h"
#include "Poco/Net/OAuth20Credentials.h"

namespace OpenWifi {

	namespace {
		inline bool IsAdminUserCaller(const SecurityObjects::UserInfo &User) {
			return User.userRole == SecurityObjects::ROOT || User.userRole == SecurityObjects::ADMIN;
		}
	}

	void RESTAPI_users_handler::DoGet() {

		bool IdOnly = (GetParameter("idOnly", "false") == "true");
		auto nameSearch = GetParameter("nameSearch");
		auto emailSearch = GetParameter("emailSearch");

		std::string baseQuery;
		if (!nameSearch.empty() || !emailSearch.empty()) {
			if (!nameSearch.empty())
				baseQuery = fmt::format(" Lower(name) like('%{}%') ",
										ORM::Escape(Poco::toLower(nameSearch)));
			if (!emailSearch.empty())
				baseQuery += baseQuery.empty()
								 ? fmt::format(" Lower(email) like('%{}%') ",
											   ORM::Escape(Poco::toLower(emailSearch)))
								 : fmt::format(" and Lower(email) like('%{}%') ",
											   ORM::Escape(Poco::toLower(emailSearch)));
		}

		SecurityObjects::UserInfoAndPolicy SecObj;

		if (Internal_) {
			// On the internal router, strictly require authenticated microservices (via X-INTERNAL-NAME)
			if (!Request->has("X-INTERNAL-NAME")) {
				return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
			}

			// Validate user delegation via Authorization: Bearer <token> header (strictly requiring Bearer scheme)
			std::string userToken;
			try {
				Poco::Net::OAuth20Credentials Auth(*Request);
				if (Poco::icompare(Auth.getScheme(), "bearer") == 0) {
					userToken = Auth.getBearerToken();
				}
			} catch (const Poco::Exception &) {
			}

			if (userToken.empty()) {
				return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
			}

			bool Expired = false;
			if (!AuthService()->IsValidToken(userToken, SecObj.webtoken, SecObj.userinfo, Expired) || Expired) {
				return Expired ? UnAuthorized(RESTAPI::Errors::EXPIRED_TOKEN)
							   : UnAuthorized(RESTAPI::Errors::INVALID_TOKEN);
			}

			const auto &callerInfo = SecObj.userinfo;
			if (callerInfo.userRole == SecurityObjects::ROOT) {
				// ROOT scope: sees all users
			} else if (callerInfo.userRole == SecurityObjects::ADMIN) {
				// ADMIN scope: only see users created by this admin
				auto Scope = fmt::format(" createdby='{}' ", ORM::Escape(callerInfo.id));
				baseQuery = baseQuery.empty() ? Scope : fmt::format("{} and {}", Scope, baseQuery);
			} else {
				// Non-admin callers (CSR, SUBSCRIBER, etc.) cannot list users
				return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
			}
		} else {
			// On the public router, strictly require ROOT or ADMIN user token
			if (!IsAdminUserCaller(UserInfo_.userinfo)) {
				return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
			}

			if (UserInfo_.userinfo.userRole == SecurityObjects::ADMIN) {
				auto AdminScope = fmt::format(" createdby='{}' ", ORM::Escape(UserInfo_.userinfo.id));
				baseQuery = baseQuery.empty() ? AdminScope : fmt::format("{} and {}", AdminScope, baseQuery);
			}
		}

		const auto &effectiveUserInfoPolicy = Internal_ ? SecObj : UserInfo_;
		const auto &effectiveUserInfo = Internal_ ? SecObj.userinfo : UserInfo_.userinfo;

		if (QB_.Select.empty()) {
			SecurityObjects::UserInfoList Users;
			if (StorageService()->UserDB().GetUsers(QB_.Offset, QB_.Limit, Users.users,
													baseQuery)) {
				for (auto &i : Users.users) {
					Sanitize(effectiveUserInfoPolicy, i);
				}
				if (IdOnly) {
					Poco::JSON::Array Arr;
					for (const auto &i : Users.users)
						Arr.add(i.id);
					Poco::JSON::Object Answer;
					Answer.set("users", Arr);
					return ReturnObject(Answer);
				}
			}
			Poco::JSON::Object Answer;
			Users.to_json(Answer);
			return ReturnObject(Answer);
		} else {
			SecurityObjects::UserInfoList Users;
			for (auto &i : SelectedRecords()) {
				SecurityObjects::UserInfo UInfo;
				if (StorageService()->UserDB().GetUserById(i, UInfo)) {
					if (!ACLProcessor::CanReadUserRecord(effectiveUserInfo, UInfo)) {
						continue;
					}
					Sanitize(effectiveUserInfoPolicy, UInfo);
					Users.users.emplace_back(UInfo);
				}
			}
			Poco::JSON::Object Answer;
			Users.to_json(Answer);
			return ReturnObject(Answer);
		}
	}
} // namespace OpenWifi
