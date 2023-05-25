const debug = require('debug')('idm:authregistry_controller');
const Ajv = require('ajv');
const ajv = new Ajv();
const fs = require('fs');
const path = require('path');
const moment = require('moment');
const oauth2_server = require('oauth2-server'); //eslint-disable-line snakecase/snakecase
const uuid = require('uuid');

const config_service = require('../../lib/configService.js');
const models = require('../../models/models');
const utils = require('../../controllers/extparticipant/utils');
const Request = oauth2_server.Request;
const Response = oauth2_server.Response;

const config = config_service.get_config();
const delegation_evidence_schema = JSON.parse(fs.readFileSync(path.join(__dirname, 'delegationEvidenceSchema.json')));
const validate_delegation_evicence = ajv.compile(delegation_evidence_schema);
const delegation_request_schema = JSON.parse(fs.readFileSync(path.join(__dirname, 'delegationRequestSchema.json')));
const validate_delegation_request = ajv.compile(delegation_request_schema);

// Create Oauth Server model
const oauth2 = new oauth2_server({ //eslint-disable-line new-cap
  model: require('../../models/model_oauth_server.js'),
  debug: true
});


const authenticate_bearer = async function authenticate_bearer(req) {
  const options = {};

  const request = new Request({
    headers: { authorization: req.headers.authorization },
    method: "POST",
    query: {}
  });

  const response = new Response();

  return await oauth2.authenticate(request, response, options);
}

const get_delegation_evidence = async function get_delegation_evidence(subject) {
  const evidence = await models.delegation_evidence.findOne({
    where: {
      policy_issuer: config.pr.client_id,
      access_subject: subject
    }
  });
  return evidence == null ? null : evidence.policy;
};

const arrays_are_equal = async function arrays_are_equal(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;

  a.sort();
  b.sort();

  for (var i = 0; i < a.length; ++i) {
    if (a[i] !== b[i]) return false;
  }

  return true;
}

const _retrieve_policy = async function _retrieve_policy(req, res) {
    const token_info = await authenticate_bearer(req);

    const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
    if (!token_info.user.admin && token_info.user.email !== authorized_email) {
      res.status(403).json({
        error: "You are not authorized to retrieve policies",
        details: validate_delegation_evicence.errors
      });
      return true;
    }

    if (req.query.accessSubject == null) {
        res.status(400).json({
          error: "Missing 'accessSubject' query parameter"
        });
        return true;
    }

    debug('Requesting available delegation evidences');

    const evidence = await get_delegation_evidence(req.query.accessSubject);
    if (evidence == null) {
      res.status(404).json({
        error: "Didn't find any policy with access subject equal to " + req.query.accessSubject
      });
      return true;
    }

    return res.status(200).json({evidence});
}

const _delete_policy = async function _delete_policy(req, res) {
  const token_info = await authenticate_bearer(req);

  const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
  if (!token_info.user.admin && token_info.user.email !== authorized_email) {
    res.status(403).json({
      error: "You are not authorized to delete policies",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  if (req.query.accessSubject == null) {
      res.status(400).json({
        error: "Missing 'accessSubject' query parameter"
      });
      return true;
  }

  debug('Deleting available delegation evidences');

  await models.delegation_evidence.destroy({
    where: {
      policy_issuer: config.pr.client_id,
      access_subject: req.query.accessSubject
    }
  });

  return res.status(200).json({});
}

const _upsert_policy = async function _upsert_policy(req, res) {
  const token_info = await authenticate_bearer(req);

  const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
  if (!token_info.user.admin && token_info.user.email !== authorized_email) {
    res.status(403).json({
      error: "You are not authorized to update policies",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  debug(`User ${token_info.user.username}`);
  if (!validate_delegation_evicence(req.body)) {
    debug(validate_delegation_evicence.errors);
    res.status(400).json({
      error: "Invalid policy document",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  const evidence = req.body.delegationEvidence;

  // Check policyIssuer
  if (evidence.policyIssuer !== config.pr.client_id) {
    res.status(422).json({
      error: `Invalid value for policyIssuer: ${evidence.policyIssuer}`
    });
    return true;
  }

  models.delegation_evidence.upsert({
    policy_issuer: evidence.policyIssuer,
    access_subject: evidence.target.accessSubject,
    policy: evidence
  });

  return res.status(200).json({});
};

const _upsert_merge_policy = async function _upsert_merge_policy(req, res) {
  const token_info = await authenticate_bearer(req);

  const authorized_email = `${config.pr.client_id}@${config.pr.url}`;
  if (!token_info.user.admin && token_info.user.email !== authorized_email) {
    res.status(403).json({
      error: "You are not authorized to update policies",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  debug(`User ${token_info.user.username}`);
  if (!validate_delegation_evicence(req.body)) {
    debug(validate_delegation_evicence.errors);
    res.status(400).json({
      error: "Invalid policy document",
      details: validate_delegation_evicence.errors
    });
    return true;
  }

  const evidence = req.body.delegationEvidence;

  // Check policyIssuer
  if (evidence.policyIssuer !== config.pr.client_id) {
    res.status(422).json({
      error: `Invalid value for policyIssuer: ${evidence.policyIssuer}`
    });
    return true;
  }

  let evidence_current = await get_delegation_evidence(evidence.target.accessSubject);
  if (evidence_current != null)
  {
    // TODO multiple policy sets
    // TODO rule exceptions

    // Make a list containing all new types (type + id combination)
    let p_types = [];
    for (let p_idx = 0; p_idx < evidence.policySets[0].policies.length; p_idx++) {
      const p_resource = evidence.policySets[0].policies[p_idx].target.resource;
      const p_actions = evidence.policySets[0].policies[p_idx].actions;

      if (!p_types.hasOwnProperty(p_resource.type)) {
        p_types[p_resource.type] = [];
      }

      // Collect type + id combo's per actions and attributes
      const p_obj_prev_idx = p_types[p_resource.type].findIndex(obj => arrays_are_equal(obj.actions, p_actions) && arrays_are_equal(obj.attrs, p_resource.attributes));
      if (p_obj_prev_idx != -1) {
        p_types[p_resource.type][p_obj_prev_idx].idx.push(p_idx);
        p_types[p_resource.type][p_obj_prev_idx].ids.push(...p_resource.identifiers);
      }
      else {
        let p_obj = {idx: [p_idx], ids: p_resource.identifiers, actions: p_actions, attrs: p_resource.attributes};
        p_types[p_resource.type].push(p_obj);
      }
    }

    // Remove these types from the currently stored policy definition
    for (let p_current_idx = 0; p_current_idx < evidence_current.policySets[0].policies.length; p_current_idx++) {
      const p_current_rules = evidence_current.policySets[0].policies[p_current_idx].rules;
      const p_current_resource = evidence_current.policySets[0].policies[p_current_idx].target.resource;
      const p_current_actions = evidence_current.policySets[0].policies[p_current_idx].target.actions;
      
      // Policy has the same type as one of the new policies
      if (p_types.hasOwnProperty(p_current_resource.type)) {
        // Search whether there is a policy with same actions and same attributes with no exceptions
        const p_same_actions_idx = p_types[p_current_resource.type].findIndex(obj => arrays_are_equal(obj.actions, p_current_actions) && arrays_are_equal(obj.attrs, p_current_resource.attributes));
        return res.status(200).json({
          idx: p_same_actions_idx,
          types: p_types.length
        });
        if (p_same_actions_idx != -1 && p_current_rules.length == 1) {
          /*for (let p_ids_idx = 0; p_ids_idx < p_types[p_current_resource.type][p_same_actions_idx].ids.length; p_ids_idx++) {
            const p_id = p_types[p_current_resource.type][p_same_actions_idx].ids[p_ids_idx];
            if (!p_current_resource.identifiers.includes(p_id)) {
              p_current_resource.identifiers.push(p_id);
              p_types[p_current_resource.type][p_same_actions_idx].ids.splice(p_ids_idx, 1);
              p_ids_idx--;
            }
          }*/

          // Remove new policy combination if empty
          if (p_types[p_current_resource.type][p_same_actions_idx].ids.length == 0) {
            p_types[p_current_resource.type].splice(p_same_actions_idx, 1);
          }
        }
        else {
          for (let p_current_ids_idx = 0; p_current_ids_idx < p_current_resource.identifiers; p_current_ids_idx++) {
            //if (p_types[p_current_resource.type].some(obj => obj.ids.includes(p_current_resource.identifiers[p_current_ids_idx]))) {
              p_current_resource.identifiers.splice(p_current_ids_idx, 1);
              p_current_ids_idx--;
            //}
          }
        }

        // Remove policy if empty
        if (p_current_resource.identifiers.length == 0) {
          evidence_current.policySets[0].policies.splice(p_current_idx, 1);
        }
      }
    }

    // Add the new policies to the policy definition
    // TODO exceptions to the rule
    for (let type in p_types) {
      if (p_types.hasOwnProperty(type)) {
        for (let t_idx = 0; t_idx < p_types[type].length; t_idx++) {
          const p_id_first = p_types[type][t_idx].idx[0];
          let p = evidence.policySets[0].policies[p_id_first];
          for (let p_id_idx = 1; p_id_idx < p_types[type][t_idx].ids.length; p_id_idx++) {
            const p_id = p_types[type][t_idx].ids[p_id_idx];
            if (!p.target.resource.identifiers.includes(p_id)) {
              p.target.resource.identifiers.push(p_id);
            }
          }
          evidence_current.policySets[0].policies.push(p);
        }
      }
   }
  }
  else {
    evidence_current = evidence;
  }

  models.delegation_evidence.upsert({
    policy_issuer: evidence_current.policyIssuer,
    access_subject: evidence_current.target.accessSubject,
    policy: evidence_current
  });

  return res.status(200).json({});
};

const is_matching_policy = function is_matching_policy(policy_mask, policy) {
  // Check resource type
  if (policy.target.resource.type !== policy_mask.target.resource.type) {
    return false;
  }

  // Check provider
  if (policy.target.environment != null) {
    if (policy_mask.target.environment == null) {
      return false;
    }

    const service_providers_mask = policy_mask.target.environment.serviceProviders;
    const service_providers = policy.target.environment.serviceProviders;
    const all_mask_sp = service_providers_mask.every(sp => service_providers.has(sp));
    if (!all_mask_sp) {
      return false;
    }
  }

  const resource = policy.target.resource;

  // Check identifiers
  const id_match = policy_mask.target.resource.identifiers.every(
    mid => {return resource.identifiers.length === 1 && resource.identifiers.includes("*") || resource.identifiers.includes(mid);}
  );
  if (!id_match) {
    return false;
  }

  // Check attributes
  const attributes_match = policy_mask.target.resource.attributes.every(
    aid => {return resource.attributes.length === 1 && resource.attributes.includes("*") || resource.attributes.includes(aid);}
  );
  if (!attributes_match) {
    return false;
  }

  // Check actions
  return policy_mask.target.actions != null &&
         policy_mask.target.actions.length > 0 &&
         policy_mask.target.actions.every(
           mact => {return policy.target.actions.length === 1 && policy.target.actions.includes("*") || policy.target.actions.includes(mact);}
         );
};

const is_denying_permission = function is_denying_permission(policy_mask, policy) {
  return policy.rules.reverse().some(rule => rule.effect === "Deny" &&
      rule.target.resource.type === policy_mask.target.resource.type &&
      (rule.target.resource.identifiers.includes("*") || policy_mask.target.resource.identifiers.some(i => rule.target.resource.identifiers.includes(i))) &&
      (rule.target.resource.attributes.includes("*") || policy_mask.target.resource.attributes.some(a => rule.target.resource.attributes.includes(a))) &&
      (rule.target.actions.length === 0 || rule.target.actions.includes("*") || policy_mask.target.actions.some(a => rule.target.actions.includes(a)))
  );
};

const _query_evidences = async function _query_evidences(req, res) {
  const token_info = await authenticate_bearer(req);

  debug(`Requesting delegation evidences affecing user ${token_info.user.username} (id: ${token_info.user.id})`);

  debug('Validating delegation mask structure');

  if (!validate_delegation_request(req.body)) {
    debug(validate_delegation_request.errors);
    res.status(400).json({
      error: "Invalid mask document",
      details: validate_delegation_request.errors
    });
    return true;
  }
  const mask = req.body.delegationRequest;

  debug('Requesting available delegation evidences');

  const evidence = await get_delegation_evidence(mask.target.accessSubject);
  if (evidence == null) {
    res.status(404).end();
    return true;
  }

  debug('Filtering delegation evidence using the provided mask');

  const new_policy_sets = mask.policySets.flatMap((policy_set_mask, i) => {

    debug(`Processing policy set ${i} from the providen mask`);

    return evidence.policySets.map((policy_set, j) => {
      debug(`  Processing policy set ${j} from the available delegation evidence`);

      const response_policy_set = {
        maxDelegationDepth: policy_set.maxDelegationDepth, //eslint-disable-line snakecase/snakecase
        target: policy_set.target
      };

      response_policy_set.policies = policy_set_mask.policies.map((policy_mask, z) => {
        debug(`    Processing policy ${z} from the current policy set`);
        const matching_policies = policy_set.policies.filter((policy) => is_matching_policy(policy_mask, policy));
        return {
          target: policy_mask.target,
          rules: [{
            effect: (matching_policies.length === 0 || matching_policies.some(p => is_denying_permission(policy_mask, p))) ? "Deny": "Permit"
          }]
        };
      });

      return response_policy_set;
    });
  });
  evidence.policySets = new_policy_sets;

  const now = moment();
  const iat = now.unix();
  const exp = now.add(30, 'seconds').unix();
  const delegation_token = await utils.create_jwt({
    iss: config.pr.client_id,
    sub: mask.target.accessSubject,
    jti: uuid.v4(),
    iat,
    exp,
    aud: token_info.user.id,
    delegationEvidence: evidence  // eslint-disable-line snakecase/snakecase
  });

  debug("Delegation evidence processed");
  res.status(200).json({delegation_token});

  return false;
};

exports.oauth2 = oauth2;
exports.get_delegation_evidence = get_delegation_evidence;
exports.upsert_policy = function upsert_policy(req, res, next) {
  debug(' --> upsert policy');
  _upsert_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.upsert_merge_policy = function upsert_merge_policy(req, res, next) {
  debug(' --> upsert merge policy');
  _upsert_merge_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.delete_policy = function delete_policy(req, res, next) {
  debug(' --> delete policy');
  _delete_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.retrieve_policy = function retrieve_policy(req, res, next) {
  debug(' --> retrieve policy');
  _retrieve_policy(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status = err.code);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};

exports.query_evidences = function query_evidences(req, res, next) {
  debug(' --> delegate');
  _query_evidences(req, res).then(
    (skip) => {
      if (!skip) {
        next();
      }
    },
    (err) => {
      if (err instanceof oauth2_server.OAuthError) {
        debug('Error ', err.message);
        if (err.details) {
          debug('Due: ', err.details);
        }
        res.status(err.status);

        res.locals.error = err;
        res.render('errors/oauth', {
          query: {},
          application: req.application
        });
      } else {
        res.status(500).json({
          message: err,
          code: 500,
          title: 'Internal Server Error'
        });
      }
    }
  );
};