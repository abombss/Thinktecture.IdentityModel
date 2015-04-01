/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see LICENSE
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace Thinktecture.IdentityModel.WebApi
{
    public class ResourceAuthorizeAttribute : FilterAttribute, IAuthorizationFilter
    {
        private string _action;
        private string[] _resources;

        public ResourceAuthorizeAttribute()
        { }

        public ResourceAuthorizeAttribute(string action, params string[] resources)
        {
            _action = action;
            _resources = resources;
        }

        public async Task<HttpResponseMessage> ExecuteAuthorizationFilterAsync(
            HttpActionContext actionContext,
            CancellationToken cancellationToken,
            Func<Task<HttpResponseMessage>> continuation)
        {
            var actions = new List<Claim>();

            var action = ActionFromAttribute();
            if (action != null) actions.Add(action);

            actions.Add(actionContext.ActionFromController());

            var resources = new List<Claim>();
            var resourceList = ResourcesFromAttribute();
            if (resourceList != null) resources.AddRange(resourceList);
            resources.AddRange(actionContext.ResourceFromController());

            // filter "controller" since we're already adding it explicitly in the above code
            var routeClaims = actionContext.ResourcesFromRouteParameters().Where(x => x.Type != "controller");
            resources.AddRange(routeClaims);

            var result =
                await
                    CheckAccessAsync(
                        actionContext.Request,
                        actions.ToArray(),
                        resources.Distinct(new ClaimComparer()).ToArray(),
                        cancellationToken);

            if (!result)
            {
                return HandleUnauthorizedRequest(actionContext);
            }

            return await continuation();
        }

        protected virtual Task<bool> CheckAccessAsync(HttpRequestMessage request, Claim[] actions, Claim[] resources, CancellationToken cancellationToken)
        {
            return request.CheckAccessAsync(actions, resources, cancellationToken);
        }

        private Claim ActionFromAttribute()
        {
            return !string.IsNullOrWhiteSpace(_action) ? new Claim("name", _action) : null;
        }

        private List<Claim> ResourcesFromAttribute()
        {
            if ((_resources != null) && (_resources.Any()))
            {
                return _resources.Select(r => new Claim("name", r)).ToList();
            }

            return null;
        }

        protected HttpResponseMessage HandleUnauthorizedRequest(HttpActionContext actionContext)
        {
            if (actionContext.ControllerContext.RequestContext.Principal != null &&
                actionContext.ControllerContext.RequestContext.Principal.Identity != null &&
                actionContext.ControllerContext.RequestContext.Principal.Identity.IsAuthenticated)
            {
                return actionContext.ControllerContext.Request.CreateErrorResponse(HttpStatusCode.Forbidden, "Forbidden");
            }

            return actionContext.ControllerContext.Request.CreateErrorResponse(HttpStatusCode.Unauthorized, "Unauthorized");
        }
    }
}