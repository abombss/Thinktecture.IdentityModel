/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see LICENSE
 */

using Microsoft.Owin;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityModel.Owin.ResourceAuthorization;
using Thinktecture.IdentityModel.WebApi;

namespace System.Net.Http
{
    public static class HttpRequestMessageExtensions
    {
        public static bool CheckAccess(this HttpRequestMessage request, string action, params string[] resources)
        {
            return AsyncHelper.RunSync(() => request.CheckAccessAsync(action, CancellationToken.None, resources));
        }

        public static Task<bool> CheckAccessAsync(this HttpRequestMessage request, string action, CancellationToken cancellationToken, params string[] resources)
        {
            var user = request.GetRequestContext().Principal as ClaimsPrincipal;
            user = user ?? Principal.Anonymous;
            
            var ctx = new ResourceAuthorizationContext(cancellationToken, user, action, resources);
            
            return request.CheckAccessAsync(ctx);
        }
        
        public static Task<bool> CheckAccessAsync(this HttpRequestMessage request, IEnumerable<Claim> actions, IEnumerable<Claim> resources, CancellationToken cancellationToken)
        {
            var authorizationContext = new ResourceAuthorizationContext(
                request.GetOwinContext().Authentication.User ?? Principal.Anonymous,
                actions,
                resources,
                cancellationToken);

            return request.CheckAccessAsync(authorizationContext);
        }

        public static Task<bool> CheckAccessAsync(this HttpRequestMessage request, ResourceAuthorizationContext authorizationContext)
        {
            return request.GetOwinContext().CheckAccessAsync(authorizationContext);
        }

        private static async Task<bool> CheckAccessAsync(this IOwinContext context, ResourceAuthorizationContext authorizationContext)
        {
            return await context.GetAuthorizationManager().CheckAccessAsync(authorizationContext);
        }

        private static IResourceAuthorizationManager GetAuthorizationManager(this IOwinContext context)
        {
            var am = context.Get<IResourceAuthorizationManager>(ResourceAuthorizationManagerMiddleware.Key);

            if (am == null)
            {
                throw new InvalidOperationException("No AuthorizationManager set.");
            }

            return am;
        }
    }
}