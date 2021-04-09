// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using NuGet.Test.Utility;
using Xunit;

namespace NuGet.Configuration.Test
{
    public class PackageSourceNamespacesItemTests
    {
        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void Constructor_WithInvalidKey_Throws(string key)
        {
            Assert.Throws<ArgumentException>(() => new PackageSourceNamespacesItem(key, new List<NamespaceItem>() { new NamespaceItem("stuff") }));
        }

        [Fact]
        public void Constructor_WithEmptyNamespaces_Throws()
        {
            Assert.Throws<ArgumentException>(() => new PackageSourceNamespacesItem("name", new List<NamespaceItem>() { }));
        }

        [Fact]
        public void Constructor_WithNullNamespaces_Throws()
        {
            Assert.Throws<ArgumentException>(() => new PackageSourceNamespacesItem("name", null));
        }

        [Fact]
        public void PackageSourceNamespacesItemParse_WithValidData_ParsesCorrectly()
        {
            // Arrange
            var config = @"
<configuration>
    <packageNamespaces>
        <packageSource key=""nuget.org"">
            <namespace key=""sadas"" />
        </packageSource>
    </packageNamespaces>
</configuration>";
            var nugetConfigPath = "NuGet.Config";
            using var mockBaseDirectory = TestDirectory.Create();
            SettingsTestUtils.CreateConfigurationFile(nugetConfigPath, mockBaseDirectory, config);

            // Act and Assert
            var settingsFile = new SettingsFile(mockBaseDirectory);
            var section = settingsFile.GetSection("packageNamespaces");
            section.Should().NotBeNull();

            section.Items.Count.Should().Be(1);
            var packageSourceNamespaceItem = section.Items.First() as PackageSourceNamespacesItem;
            var item = packageSourceNamespaceItem.Namespaces.First();
            var expectedItem = new NamespaceItem("sadas");
            SettingsTestUtils.DeepEquals(item, expectedItem).Should().BeTrue();
        }
    }
}
