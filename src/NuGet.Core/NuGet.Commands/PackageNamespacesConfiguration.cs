// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using NuGet.Common;
using NuGet.Configuration;

namespace NuGet.Commands
{
    public class PackageNamespacesConfiguration
    {
        public bool IsStrict { get; }

        public Dictionary<string, IReadOnlyList<string>> Namespaces { get; }

        public PackageNamespacesConfiguration(bool isStrict, Dictionary<string, IReadOnlyList<string>> namespaces)
        {
            IsStrict = isStrict;
            Namespaces = namespaces;
        }

        public static PackageNamespacesConfiguration GetPackageNamespacesConfiguration(ISettings settings, ILogger logger)
        {
            if (settings == null)
            {
                throw new ArgumentNullException(nameof(settings));
            }

            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            // var policy = SettingsUtility.GetSignatureValidationMode(settings);

            return new PackageNamespacesConfiguration(isStrict: false, new Dictionary<string, IReadOnlyList<string>>());
        }
    }
}
