/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React, { useState, useEffect } from 'react';
import ReactApexChart from 'react-apexcharts';
import { ApexOptions } from 'apexcharts';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { useTheme } from 'styled-components';
import { Icon } from 'components';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import { ChartBarStacked } from 'helpers/interfaces/ChartData';
import { formatChartStacked } from 'helpers/formatters/chartData';
import { AxiosResponse } from 'axios';

interface Props {
  filters?: FilterValues;
}

const VulnerabilitiesByDeveloper: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();

  const [isLoading, setLoading] = useState(false);
  const [chartData, setChartData] = useState<ChartBarStacked>({
    categories: [],
    series: [],
  });

  const [chartDataAux, setChartDataAux] = useState<ChartBarStacked>({
    categories: [],
    series: [],
  });

  const options: ApexOptions = {
    markers: {
      size: 0,
    },
    colors: Object.values(colors.vulnerabilities),
    noData: {
      text: t('DASHBOARD_SCREEN.CHART_NO_DATA'),
      style: {
        color: colors.chart.legend,
      },
    },
    legend: {
      position: 'top',
      horizontalAlign: 'left',
      offsetX: 40,
      labels: {
        colors: colors.chart.legend,
      },
    },
    chart: {
      fontFamily: 'SFRegular',
      stacked: true,
      animations: {
        enabled: false,
      },
      toolbar: {
        show: false,
      },
      events: {
        click: (_event, _chartContext, config) => {
          const { seriesIndex } = config;
          setChartData((state) => {
            const category = state.series[seriesIndex];
            let categories = [];
            let series = [];
            if (category) {
              categories = [category.name];
              series = [
                { name: 'Vulnerability', data: [1] },
                { name: 'Risk Accepted', data: [1] },
                { name: 'False Positive', data: [1] },
                { name: 'Corrected', data: [1] },
              ];
              return { categories, series };
            } else {
              return state;
            }
          });
        },
      },
    },
    plotOptions: {
      bar: {
        horizontal: true,
      },
    },
    xaxis: {
      labels: {
        style: {
          colors: colors.chart.legend,
        },
      },
      categories: [],
    },
    yaxis: {
      title: {
        text: undefined,
      },
      labels: {
        style: {
          colors: colors.chart.legend,
        },
      },
    },
  };

  useEffect(() => {
    let isCancelled = false;

    if (filters) {
      setLoading(true);

      analyticService
        .getVulnerabilitiesByDeveloper(filters)
        .then((result: AxiosResponse) => {
          if (!isCancelled) {
            const data = formatChartStacked(result.data.content, 'developer');
            setChartData(data);
            setChartDataAux(data);
          }
        })
        .finally(() => {
          if (!isCancelled) {
            setLoading(false);
          }
        });
    }

    return () => {
      isCancelled = true;
    };
  }, [filters]);

  return (
    <div className="block max-space">
      <Styled.Wrapper>
        <Styled.Title>
          {t('DASHBOARD_SCREEN.VULNERABILITIES_BY_DEV')}
          <button onClick={() => setChartData(chartDataAux)}>Refresh</button>
        </Styled.Title>

        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <ReactApexChart
          height={250}
          width="100%"
          options={{
            ...options,
            xaxis: { ...options.xaxis, categories: chartData.categories },
          }}
          series={chartData.series}
          type="bar"
        />
      </Styled.Wrapper>
    </div>
  );
};

export default VulnerabilitiesByDeveloper;
