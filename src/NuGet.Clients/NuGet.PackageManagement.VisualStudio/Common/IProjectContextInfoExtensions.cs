// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable enable

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft;
using Microsoft.ServiceHub.Framework;
using NuGet.Common;
using NuGet.Frameworks;
using NuGet.Packaging.Core;
using NuGet.VisualStudio.Internal.Contracts;

namespace NuGet.PackageManagement.VisualStudio
{
    public static class IProjectContextInfoExtensions
    {
        public static async ValueTask<bool> IsUpgradeableAsync(
            this IProjectContextInfo projectContextInfo,
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
            Assumes.NotNull(projectContextInfo);
            Assumes.NotNull(serviceBroker);

            cancellationToken.ThrowIfCancellationRequested();

            using (INuGetProjectUpgraderService? projectUpgrader = await serviceBroker.GetProxyAsync<INuGetProjectUpgraderService>(
                NuGetServices.ProjectUpgraderService,
                cancellationToken: cancellationToken))
            {
                Assumes.NotNull(projectUpgrader);

                return await projectUpgrader.IsProjectUpgradeableAsync(projectContextInfo.ProjectId, cancellationToken);
            }
        }

        public static async ValueTask<IReadOnlyCollection<IPackageReferenceContextInfo>> GetInstalledPackagesAsync(
            this IProjectContextInfo projectContextInfo,
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
            Assumes.NotNull(projectContextInfo);
            Assumes.NotNull(serviceBroker);

            cancellationToken.ThrowIfCancellationRequested();
            //TODO: remove this
            var projectContext = await NuGet.VisualStudio.ServiceLocator.GetInstanceAsync<ProjectManagement.INuGetProjectContext>();
            var stopWatch = Stopwatch.StartNew();
            //var telemetryEvent2 = new Telemetry.GetInstalledPackagesAsyncTelemetryEvent();
            //telemetryEvent2["projectIds"] = projectContextInfo.ProjectId;
            //telemetryEvent2["projectIdsCount"] = 1;
            //telemetryEvent2["stack"] = System.Environment.StackTrace;
            //NuGet.Common.TelemetryActivity.EmitTelemetryEvent(telemetryEvent2);

            using (INuGetProjectManagerService projectManager = await GetProjectManagerAsync(serviceBroker, cancellationToken))
            {
                IReadOnlyDictionary<string, IReadOnlyCollection<IPackageReferenceContextInfo>>? dictionary =
                    await projectManager.GetInstalledPackagesAsync(new string[] { projectContextInfo.ProjectId }, cancellationToken);

                var returnMe = dictionary.Values.SelectMany(packages => packages).ToList().AsReadOnly();
                var time = DatetimeUtility.ToReadableTimeFormat(stopWatch.Elapsed);
                projectContext?.Log(ProjectManagement.MessageLevel.Info, "----\tIProjectContextInfoExtensions.GetInstalledPackagesAsync(this IProjectContextInfo projectContextInfo, projectContextInfos,,)\t\tDuration\t\t " + time + " -----");
                return returnMe;
            }
        }

        /// <summary>
        /// Gets installed packages for each project, and returns a dictionary mapping ProjectID to installed PackageReferences.
        /// </summary>
        /// <param name="projectContextInfos"></param>
        /// <param name="serviceBroker"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public static async ValueTask<IReadOnlyDictionary<string, IReadOnlyCollection<IPackageReferenceContextInfo>>> GetInstalledPackagesAsync(
            this IEnumerable<IProjectContextInfo> projectContextInfos,
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
            Assumes.NotNull(projectContextInfos);
            Assumes.NotNull(serviceBroker);

            cancellationToken.ThrowIfCancellationRequested();

            //TODO: remove this
            var projectContext = await NuGet.VisualStudio.ServiceLocator.GetInstanceAsync<ProjectManagement.INuGetProjectContext>();
            var stopWatch = Stopwatch.StartNew();

            //var telemetryEvent2 = new Telemetry.GetInstalledPackagesAsyncTelemetryEvent();
            //telemetryEvent2["projectIds"] = string.Join("; ", projectIds);
            //telemetryEvent2["projectIdsCount"] = projectIds.Count;
            //telemetryEvent2["stack"] = System.Environment.StackTrace;
            //NuGet.Common.TelemetryActivity.EmitTelemetryEvent(telemetryEvent2);

            ReadOnlyCollection<string>? projectIds = projectContextInfos.Select(pci => pci.ProjectId).ToList().AsReadOnly();

            if (projectIds is null)
            {
                return new Dictionary<string, IReadOnlyCollection<IPackageReferenceContextInfo>>();
            }

            using (INuGetProjectManagerService projectManager = await GetProjectManagerAsync(serviceBroker, cancellationToken))
            {
                var packages = await projectManager.GetInstalledPackagesAsync(projectIds, cancellationToken);

                var time = DatetimeUtility.ToReadableTimeFormat(stopWatch.Elapsed);
                projectContext?.Log(ProjectManagement.MessageLevel.Info, "----\tIProjectContextInfoExtensions.GetInstalledPackagesAsync(this IEnumerable<IProjectContextInfo> projectContextInfos,,)\t\tDuration\t\t " + time + " -----");

                return packages;
            }
        }

        public static async ValueTask<IInstalledAndTransitivePackages> GetInstalledAndTransitivePackagesAsync(
            this IProjectContextInfo projectContextInfo,
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
            Assumes.NotNull(projectContextInfo);
            Assumes.NotNull(serviceBroker);

            cancellationToken.ThrowIfCancellationRequested();

            //TODO: remove this
            var projectContext = await NuGet.VisualStudio.ServiceLocator.GetInstanceAsync<ProjectManagement.INuGetProjectContext>();
            var stopWatch = Stopwatch.StartNew();

            //var telemetryEvent2 = new Telemetry.GetInstalledPackagesAsyncTelemetryEvent();
            //telemetryEvent2["projectIds"] = projectContextInfo.ProjectId;
            //telemetryEvent2["projectIdsCount"] = 1;
            //telemetryEvent2["stack"] = System.Environment.StackTrace;
            //NuGet.Common.TelemetryActivity.EmitTelemetryEvent(telemetryEvent2);

            using (INuGetProjectManagerService projectManager = await GetProjectManagerAsync(serviceBroker, cancellationToken))
            {
                var returnMe = await projectManager.GetInstalledAndTransitivePackagesAsync(new string[] { projectContextInfo.ProjectId }, cancellationToken);
                var time = DatetimeUtility.ToReadableTimeFormat(stopWatch.Elapsed);
                projectContext?.Log(ProjectManagement.MessageLevel.Info, "----\tIProjectContextInfoExtensions.GetInstalledAndTransitivePackagesAsync(this IProjectContextInfo projectContextInfo,)\t\tDuration\t\t " + time + " -----");
                return returnMe;
            }
        }

        public static async ValueTask<IReadOnlyCollection<NuGetFramework>> GetTargetFrameworksAsync(
            this IProjectContextInfo projectContextInfo,
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
            Assumes.NotNull(projectContextInfo);
            Assumes.NotNull(serviceBroker);

            cancellationToken.ThrowIfCancellationRequested();

            using (INuGetProjectManagerService projectManager = await GetProjectManagerAsync(serviceBroker, cancellationToken))
            {
                return await projectManager.GetTargetFrameworksAsync(new string[] { projectContextInfo.ProjectId }, cancellationToken);
            }
        }

        public static async ValueTask<IProjectMetadataContextInfo> GetMetadataAsync(
            this IProjectContextInfo projectContextInfo,
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
            Assumes.NotNull(projectContextInfo);
            Assumes.NotNull(serviceBroker);

            cancellationToken.ThrowIfCancellationRequested();

            using (INuGetProjectManagerService projectManager = await GetProjectManagerAsync(serviceBroker, cancellationToken))
            {
                return await projectManager.GetMetadataAsync(projectContextInfo.ProjectId, cancellationToken);
            }
        }

        public static async ValueTask<string?> GetUniqueNameOrNameAsync(
            this IProjectContextInfo projectContextInfo,
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
            IProjectMetadataContextInfo metadata = await GetMetadataAsync(projectContextInfo, serviceBroker, cancellationToken);

            return metadata.UniqueName ?? metadata.Name;
        }

        public static async ValueTask<(bool, string?)> TryGetInstalledPackageFilePathAsync(
            this IProjectContextInfo projectContextInfo,
            IServiceBroker serviceBroker,
            PackageIdentity packageIdentity,
            CancellationToken cancellationToken)
        {
            Assumes.NotNull(projectContextInfo);
            Assumes.NotNull(serviceBroker);
            Assumes.NotNull(packageIdentity);

            cancellationToken.ThrowIfCancellationRequested();

            using (INuGetProjectManagerService projectManager = await GetProjectManagerAsync(serviceBroker, cancellationToken))
            {
                return await projectManager.TryGetInstalledPackageFilePathAsync(
                    projectContextInfo.ProjectId,
                    packageIdentity,
                    cancellationToken);
            }
        }

        private static async ValueTask<INuGetProjectManagerService> GetProjectManagerAsync(
            IServiceBroker serviceBroker,
            CancellationToken cancellationToken)
        {
#pragma warning disable ISB001 // Dispose of proxies
            INuGetProjectManagerService? projectManager = await serviceBroker.GetProxyAsync<INuGetProjectManagerService>(
                 NuGetServices.ProjectManagerService,
                 cancellationToken: cancellationToken);
#pragma warning restore ISB001 // Dispose of proxies

            Assumes.NotNull(projectManager);

            return projectManager;
        }
    }
}
