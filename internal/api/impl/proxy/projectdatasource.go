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
	"github.com/labstack/echo/v4"
	"github.com/perses/perses/internal/api/utils"
	v1 "github.com/perses/perses/pkg/model/api/v1"
	"github.com/perses/perses/pkg/model/api/v1/role"
	"github.com/perses/spec/go/datasource"
)

func (e *endpoint) proxyProjectDatasource(ctx echo.Context, projectName, dtsName string, spec datasource.Spec) error {
	path := ctx.Param("*")
	pr, err := newProxy(dtsName, projectName, spec, path, e.crypto, func(name string) (*v1.SecretSpec, error) {
		return e.getProjectSecret(projectName, dtsName, name)
	}, func(name string, spec *v1.SecretSpec) error {
		return e.updateProjectSecret(projectName, dtsName, name, spec)
	})
	if err != nil {
		return err
	}
	return pr.serve(ctx)
}

func (e *endpoint) proxyUnsavedProjectDatasource(ctx echo.Context) error {
	projectName := ctx.Param(utils.ParamProject)
	body := &unsavedProxyBody{}
	if err := ctx.Bind(body); err != nil {
		return err
	}

	if err := e.checkPermission(ctx, projectName, role.DatasourceScope, role.CreateAction); err != nil {
		return err
	}

	body.setRequestParams(ctx)

	dtsName := unsavedDatasourceDefaultName
	if body.Spec.Display != nil {
		dtsName = body.Spec.Display.Name
	}

	return e.proxyProjectDatasource(ctx, projectName, dtsName, body.Spec)
}

func (e *endpoint) proxySavedProjectDatasource(ctx echo.Context) error {
	projectName := ctx.Param(utils.ParamProject)
	if err := e.checkPermission(ctx, projectName, role.DatasourceScope, role.ReadAction); err != nil {
		return err
	}

	dtsName := ctx.Param(utils.ParamName)
	dts, err := e.getProjectDatasource(projectName, dtsName)
	if err != nil {
		return err
	}

	return e.proxyProjectDatasource(ctx, projectName, dtsName, dts)
}

func (e *endpoint) getProjectDatasource(projectName, name string) (datasource.Spec, error) {
	dts, err := e.dts.Get(projectName, name)
	if err != nil {
		return datasource.Spec{}, handleProjectDatasourceError(projectName, name, "get", err)
	}
	return dts.Spec, nil
}

func (e *endpoint) getProjectSecret(projectName, dtsName, name string) (*v1.SecretSpec, error) {
	scrt, err := e.secret.Get(projectName, name)
	if err != nil {
		return nil, handleProjectSecretError(projectName, dtsName, name, "get", err)
	}
	return &scrt.Spec, nil
}

func (e *endpoint) updateProjectSecret(projectName, dtsName, name string, spec *v1.SecretSpec) error {
	scrt, err := e.secret.Get(projectName, name)
	if err != nil {
		return handleProjectSecretError(projectName, dtsName, name, "get", err)
	}

	scrt.Spec = *spec

	return handleProjectSecretError(projectName, dtsName, name, "update", e.secret.Update(scrt))
}
