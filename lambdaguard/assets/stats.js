Highcharts.chart('{chartid}', {
  chart: {
    plotBackgroundColor: null,
    plotBorderWidth: 0,
    plotShadow: false,
    type: 'pie',
    height: 230
  },
  title: {
    text: '{title}'
  },
  tooltip: {
    pointFormat: '<b>{point.y} / {count}</b> ({point.percentage:.1f}%)'
  },
  plotOptions: {
    pie: {
      allowPointSelect: true,
      cursor: 'pointer',
      dataLabels: {
        enabled: true,
        format: '<b>{point.name}</b>: {point.y}',
        style: {
          color: (Highcharts.theme && Highcharts.theme.contrastTextColor) || 'black'
        }
      }
    }
  },
  series: [{
    name: '{title}',
    colorByPoint: true,
    data: {data}
  }]
});
