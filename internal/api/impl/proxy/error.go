// Copyright The Perses Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"

	databaseModel "github.com/perses/perses/internal/api/database/model"
	apiinterface "github.com/perses/perses/internal/api/interface"
	"github.com/sirupsen/logrus"
)

func handleGlobalDatasourceError(name, action string, err error) error {
	if err == nil {
		return nil
	}
	if databaseModel.IsKeyNotFound(err) {
		logrus.Debugf("unable to find the GlobalDatasource %q", name)
		return apiinterface.HandleNotFoundError(fmt.Sprintf("unable to forward the request to the GlobalDatasource %q, GlobalDatasource doesn't exist", name))
	}
	logrus.WithError(err).Errorf("unable to %s the Datasource %q, something wrong with the database", action, name)
	return apiinterface.InternalError
}

func handleGlobalSecretError(dtsName, name, action string, err error) error {
	if err == nil {
		return nil
	}
	if databaseModel.IsKeyNotFound(err) {
		logrus.Debugf("unable to find the GlobalSecret %q", name)
		return apiinterface.HandleNotFoundError(fmt.Sprintf("unable to forward the request to the GlobalDatasource %q, GlobalSecret %q attached doesn't exist", dtsName, name))
	}
	logrus.WithError(err).Errorf("unable to %s the GlobalSecret %q attached to the GlobalDatasource %q, something wrong with the database", action, name, dtsName)
	return apiinterface.InternalError
}

func handleProjectDashboardError(projectName, dashboardName, name, action string, err error) error {
	if err == nil {
		return nil
	}
	if databaseModel.IsKeyNotFound(err) {
		logrus.Debugf("unable to find the Dashboard %q in Project %q", dashboardName, projectName)
		return apiinterface.HandleNotFoundError(fmt.Sprintf("unable to forward the request to the Datasource %q from Dashboard %q in Project %q, Dashbooard doesn't exist", name, dashboardName, projectName))
	}
	logrus.WithError(err).Errorf("unable to %s the Datasource %q from Dashboard %q in Project %q, something wrong with the database", action, name, dashboardName, projectName)
	return apiinterface.InternalError
}

func handleProjectDatasourceError(projectName, name, action string, err error) error {
	if err == nil {
		return nil
	}
	if databaseModel.IsKeyNotFound(err) {
		logrus.Debugf("unable to find the Datasource %q in Project %q", name, projectName)
		return apiinterface.HandleNotFoundError(fmt.Sprintf("unable to forward the request to the Datasource %q, Datasource doesn't exist in Project %q", name, projectName))
	}
	logrus.WithError(err).Errorf("unable to %s the Datasource %q in Project %q, something wrong with the database", action, name, projectName)
	return apiinterface.InternalError
}

func handleProjectSecretError(projectName, dtsName, name, action string, err error) error {
	if err == nil {
		return nil
	}
	if databaseModel.IsKeyNotFound(err) {
		logrus.Debugf("unable to find the Secret %q in Project %q", name, projectName)
		return apiinterface.HandleNotFoundError(fmt.Sprintf("unable to forward the request to the Datasource %q, Secret %q attached doesn't exist in Project %q", dtsName, name, projectName))
	}
	logrus.WithError(err).Errorf("unable to %s the Secret %q attached to the Datasource %q in Project %q, something wrong with the database", action, name, dtsName, projectName)
	return apiinterface.InternalError
}
